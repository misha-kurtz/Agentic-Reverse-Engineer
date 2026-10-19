# binary-eval/workflows/payload_recovery/runtime_decrypt.py
from __future__ import annotations
import re
import struct

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

import pefile

from runners.debugger import CdbDebugger, ModuleInfo

'''
Hyperion Runtime Decryption Workflow

Payload recovery: Confirm Hyperion has decrypted the original PE into the intermediate buffer.

OEP discovery: Extract the candidate OEP RVA from the decrypted PE headers.

Runtime confirmation: Verify that execution actually transfers to the recovered OEP and that 
the final mapped image is ready for dumping.
'''

'''
Encrypted entry point
        |
        v
Install Hyperion loader API breakpoints
        |
        v
Observe LoadLibraryA
        |
        v
Observe GetProcAddress
        |
        v
Observe API-resolution activity
        |
        v
Identify candidate VirtualAlloc
        |
        v
Validate allocation arguments
        |
        v
Return to caller and capture RAX
        |
        v
Locate REP MOVSQ
        |
        v
Verify source, destination, and copy size
        |
        v
Track original ciphertext source
        |
        v
Detect decrypted PE headers
        |
        v
Validate recovered PE metadata
        |
        v
Extract candidate OEP RVA
        |
        v
Calculate candidate OEP VA
        |
        v
Install hardware execution breakpoint
        |
        v
Confirm execution reaches OEP
'''

class RuntimeDecryptError(RuntimeError):
    pass


@dataclass(frozen=True)
class BootstrapEvent:
    api: str
    rip: int


@dataclass(frozen=True)
class AllocationInfo:
    base: int
    size: int
    allocation_type: int
    protection: int
    return_address: int


@dataclass(frozen=True)
class CopyInfo:
    instruction_va: int
    source_va: int
    destination_va: int
    size: int


@dataclass(frozen=True)
class RecoveredSection:
    name: str
    rva: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)


@dataclass(frozen=True)
class RecoveredPE:
    buffer_va: int
    preferred_image_base: int
    image_size: int
    oep_rva: int
    sections: tuple[RecoveredSection, ...]


@dataclass(frozen=True)
class ProtectionEvent:
    address: int
    size: int
    new_protection: int
    return_address: int
    succeeded: bool = False


@dataclass(frozen=True)
class DecryptResult:
    input_path: Path
    pid: int

    encrypted_image_base: int
    encrypted_entry_rva: int

    bootstrap_events: tuple[BootstrapEvent, ...]
    protection_events: tuple[ProtectionEvent, ...]

    allocation: AllocationInfo
    copy: CopyInfo

    intermediate_pe_va: int
    recovered_image_base: int
    recovered_image_size: int

    oep_va: int
    oep_rva: int

    sections: tuple[RecoveredSection, ...]
    loaded_modules: tuple[ModuleInfo, ...]


class RuntimeDecryptor:
    '''
    Deterministic Hyperion runtime PE recovery.

    Workflow:

        Encrypted EP
            -> API bootstrap monitoring
            -> VirtualAlloc candidate
            -> Allocation return
            -> REP MOVSQ
            -> Breakpoint after REP MOVSQ
            -> Source/decryption monitoring
            -> Recovered PE header
            -> Candidate OEP
            -> VirtualProtect monitoring
            -> OEP execution confirmation
            -> Mapped-image validation

    This workflow stops at the confirmed OEP.

    IAT rebuilding and PE reconstruction are handled by
    downstream pipeline components.
    '''

    BOOTSTRAP_APIS = (
        "LoadLibraryA",
        "GetProcAddress",
        "VirtualAlloc",
        "VirtualProtect",
        "MapViewOfFile",
    )

    EVENT_MARKERS = {
        "LoadLibraryA": "HYP_LOAD",
        "GetProcAddress": "HYP_RESOLVE",
        "VirtualAlloc": "HYP_ALLOC",
        "VirtualProtect": "HYP_PROTECT",
        "MapViewOfFile": "HYP_MAP",
        "SourceWrite": "HYP_WRITE",
        "OEP": "HYP_OEP",
    }

    def __init__(
        self,
        debugger: CdbDebugger,
        max_bootstrap_events: int = 256,
        max_copy_instructions: int = 512,
        max_monitor_events: int = 2048,
        max_header_offset: int = 0x40,
    ):
        self.debugger = debugger

        self.max_bootstrap_events = max_bootstrap_events
        self.max_copy_instructions = max_copy_instructions
        self.max_monitor_events = max_monitor_events
        self.max_header_offset = max_header_offset

    # ----------------------------------------------------------
    # Public workflow
    # ----------------------------------------------------------

    def run(self, executable: Path | str) -> DecryptResult:
        executable = Path(executable)

        if not executable.exists():
            raise RuntimeDecryptError(
                f"Executable not found: {executable}"
            )

        pe = pefile.PE(str(executable))

        try:
            if pe.OPTIONAL_HEADER.Magic != 0x20B:
                raise RuntimeDecryptError(
                    "Expected PE32+ executable"
                )

            encrypted_entry_rva = (
                pe.OPTIONAL_HEADER.AddressOfEntryPoint
            )

        finally:
            pe.close()

        self.debugger.launch(executable)

        try:
            module = self.debugger.get_module(executable.name)

            image_base = module.base
            entry_va = image_base + encrypted_entry_rva

            pid = self.debugger.get_process_id()

            print(f"[hyperion] Image base: 0x{image_base:X}")
            print(f"[hyperion] Entry VA:   0x{entry_va:X}")

            # Stop at the encrypted entry point.
            self.debugger.set_breakpoint(entry_va)
            self.debugger.continue_execution()

            self._require_rip(entry_va)
            self.debugger.clear_all_breakpoints()

            # Observe loader bootstrap and allocation.
            bootstrap_events, allocation = (
                self._observe_loader_bootstrap()
            )

            # Identify and complete the encrypted-data copy.
            copy = self._observe_bulk_copy(allocation)

            # ----------------------------------------------------------
            # NORMAL WORKFLOW (temporarily unreachable)
            # ----------------------------------------------------------

            bootstrap_events, allocation = (
                self._observe_loader_bootstrap(
                    image_base=image_base,
                    image_end=module.end,
                )
            )

            # Identify and complete the encrypted-data copy.
            copy = self._observe_bulk_copy(allocation)

            # Monitor decryption and reconstruction together.
            recovered, protection_events = (
                self._observe_decryption_and_reconstruction(
                    allocation=allocation,
                    copy=copy,
                    image_base=image_base,
                    image_end=module.end,
                )
            )

            oep_va = image_base + recovered.oep_rva

            return DecryptResult(
                input_path=executable,
                pid=pid,
                encrypted_image_base=image_base,
                encrypted_entry_rva=encrypted_entry_rva,
                bootstrap_events=bootstrap_events,
                protection_events=protection_events,
                allocation=allocation,
                copy=copy,
                intermediate_pe_va=recovered.buffer_va,
                recovered_image_base=image_base,
                recovered_image_size=recovered.image_size,
                oep_va=oep_va,
                oep_rva=recovered.oep_rva,
                sections=recovered.sections,
                loaded_modules=tuple(
                    self.debugger.get_modules()
                ),
            )

        except Exception:
            self.debugger.close()
            raise

    # ----------------------------------------------------------
    # Breakpoint management
    # ----------------------------------------------------------


    def _set_api_breakpoint(self, api: str) -> None:
        '''
        Install a CDB API breakpoint using a resolvable
        Windows API implementation.

        Verify that the breakpoint command succeeds.
        '''

        marker = self.EVENT_MARKERS[api]

        command = (
            f'bu KERNELBASE!{api} ".echo {marker}"'
        )

        output = self.debugger.command(command)

        if (
            "Couldn't resolve" in output
            or "error" in output.lower()
        ):
            raise RuntimeDecryptError(
                f"Failed to install breakpoint for {api}:\n"
                f"{output}"
            )

        print(
            f"[breakpoint] Installed KERNELBASE!{api}"
        )

    def _set_source_breakpoint(self, source_va: int) -> None:
        '''
        Monitor writes to the first eight bytes of the
        identified ciphertext source.

        This is a targeted header watchpoint, not a
        full-region memory breakpoint.
        '''

        watch_va = source_va & ~0x7

        marker = self.EVENT_MARKERS["SourceWrite"]

        self.debugger.command(
            f'ba w8 0x{watch_va:X} ".echo {marker}"'
        )

    def _set_oep_breakpoint(self, oep_va: int) -> None:
        '''
        Install a hardware execution breakpoint at the
        candidate original entry point.
        '''

        marker = self.EVENT_MARKERS["OEP"]

        self.debugger.command(
            f'ba e1 0x{oep_va:X} ".echo {marker}"'
        )

    def _classify_event(self, output: str) -> str | None:
        '''
        Classify CDB breakpoint output using exact marker lines.

        A structured stop-event API would be preferable
        for production use.
        '''

        matches = []

        for api, marker in self.EVENT_MARKERS.items():
            pattern = rf"(?m)^\s*{re.escape(marker)}\s*$"

            if re.search(pattern, output):
                matches.append(api)

        if len(matches) != 1:
            return None

        return matches[0]

    # ----------------------------------------------------------
    # Bootstrap monitoring
    # ----------------------------------------------------------

    def _observe_loader_bootstrap(
        self,
        image_base: int,
        image_end: int,
    ) -> tuple[tuple[BootstrapEvent, ...], AllocationInfo]:
        '''
        Observe the loader's API calls and identify a candidate
        VirtualAlloc allocation associated with payload recovery.

        Unlike the previous implementation, allocation inspection
        does not depend on observing LoadLibraryA or GetProcAddress
        first.

        Candidate allocations are evaluated using:
        - requested allocation size
        - allocation type
        - initial protection
        - return address
        - whether the caller belongs to the executable image
        '''

        self.debugger.clear_all_breakpoints()

        for api in self.BOOTSTRAP_APIS:
            self._set_api_breakpoint(api)

        print("\n[bootstrap] Installed CDB breakpoints:")
        print(self.debugger.command("bl"))

        events: list[BootstrapEvent] = []

        for event_index in range(self.max_bootstrap_events):

            output = self.debugger.continue_execution()

            api = self._classify_event(output)

            if api is None:
                print("[bootstrap] Unclassified debugger stop:")
                print(output)

                raise RuntimeDecryptError(
                    "Unable to classify bootstrap debugger stop."
                )

            rip = self.debugger.get_register("rip")

            print(f"[bootstrap] {api}: 0x{rip:X}")

            # Keep the existing BootstrapEvent construction here
            # if your dataclass uses additional fields.
            events.append(
                BootstrapEvent(
                    api=api,
                    address=rip,
                )
            )

            if api != "VirtualAlloc":
                continue

            registers = self.debugger.get_registers(
                "rcx",
                "rdx",
                "r8",
                "r9",
                "rsp",
            )

            requested_base = registers["rcx"]
            allocation_size = registers["rdx"]
            allocation_type = registers["r8"]
            protection = registers["r9"]

            return_address = self.debugger.read_qword(
                registers["rsp"]
            )

            caller_in_image = (
                image_base <= return_address < image_end
            )

            print(
                "\n[allocation] VirtualAlloc candidate:\n"
                f"  lpAddress:         0x{requested_base:X}\n"
                f"  dwSize:            0x{allocation_size:X}\n"
                f"  flAllocationType:  0x{allocation_type:X}\n"
                f"  flProtect:         0x{protection:X}\n"
                f"  Return address:    0x{return_address:X}\n"
                f"  Caller in image:   {caller_in_image}"
            )

            # Hyperion's observed allocation uses MEM_COMMIT |
            # MEM_RESERVE and PAGE_READWRITE.
            #
            # These values are useful candidate filters, but they
            # do not independently prove payload recovery.
            matches_allocation_pattern = (
                requested_base == 0
                and allocation_size > 0
                and (allocation_type & 0x3000) == 0x3000
                and protection == 0x04
            )

            if not matches_allocation_pattern:
                print(
                    "[allocation] Candidate rejected: "
                    "allocation arguments do not match."
                )
                continue

            if not caller_in_image:
                print(
                    "[allocation] Candidate rejected: "
                    "caller is outside the executable image."
                )
                continue

            print(
                "[allocation] Candidate matches. "
                "Waiting for VirtualAlloc return."
            )

            # Execute until the current function returns.
            self.debugger.command("gu", timeout=120.0)

            allocated_base = self.debugger.get_register("rax")

            print(
                f"[allocation] VirtualAlloc returned: "
                f"0x{allocated_base:X}"
            )

            if allocated_base == 0:
                print(
                    "[allocation] Candidate rejected: "
                    "VirtualAlloc failed."
                )
                continue

            # Construct AllocationInfo using the field names
            # from your existing dataclass.
            allocation = AllocationInfo(
                base=allocated_base,
                size=allocation_size,
                allocation_type=allocation_type,
                protection=protection,
                return_address=return_address,
            )

            self.debugger.clear_all_breakpoints()

            return tuple(events), allocation

        raise RuntimeDecryptError(
            "Bootstrap event limit reached without identifying "
            "a suitable VirtualAlloc allocation."
        )

    # ----------------------------------------------------------
    # REP MOVSQ detection
    # ----------------------------------------------------------

    def _observe_bulk_copy(
        self,
        allocation: AllocationInfo,
    ) -> CopyInfo:
        '''
        Follow execution after VirtualAlloc returns.

        Identify REP MOVSQ by disassembly and correlate
        the copy with the observed allocation.
        '''

        for _ in range(self.max_copy_instructions):
            rip = self.debugger.get_register("rip")

            instruction = self.debugger.disassemble_one(
                rip
            )

            mnemonic = instruction.mnemonic.lower()
            operands = instruction.operands.lower()

            is_movsq = (
                "movsq" in mnemonic
                or "movsq" in operands
            )

            is_repeat = (
                "rep" in mnemonic
                or b"\xF3" in instruction.raw_bytes[:2]
            )

            if not (is_movsq and is_repeat):
                self.debugger.command("p")
                continue

            registers = self.debugger.get_registers(
                "rsi", "rdi", "rcx"
            )

            source_va = registers["rsi"]
            destination_va = registers["rdi"]
            copy_size = registers["rcx"] * 8

            if (
                destination_va != allocation.base
                or copy_size != allocation.size
            ):
                self.debugger.command("p")
                continue

            print(f"[copy] Instruction: 0x{rip:X}")
            print(f"[copy] Source:      0x{source_va:X}")
            print(f"[copy] Destination: 0x{destination_va:X}")
            print(f"[copy] Size:        0x{copy_size:X}")

            self._complete_bulk_copy(
                instruction_va=rip,
                source_va=source_va,
                destination_va=destination_va,
                copy_size=copy_size,
            )

            return CopyInfo(
                instruction_va=rip,
                source_va=source_va,
                destination_va=destination_va,
                size=copy_size,
            )

        raise RuntimeDecryptError(
            "Matching REP MOVSQ not found"
        )

    def _complete_bulk_copy(
        self,
        instruction_va: int,
        source_va: int,
        destination_va: int,
        copy_size: int,
    ) -> None:
        '''
        Reproduce the manual x64dbg workflow:

        1. Identify the instruction after REP MOVSQ.
        2. Set a software breakpoint at that address.
        3. Continue execution.
        4. Validate completion using RCX, RSI, and RDI.
        '''

        instruction = self.debugger.disassemble_one(
            instruction_va
        )

        next_va = (
            instruction_va
            + len(instruction.raw_bytes)
        )

        self.debugger.clear_all_breakpoints()

        self.debugger.set_breakpoint(next_va)

        print(
            f"[copy] Completion breakpoint: 0x{next_va:X}"
        )

        self.debugger.continue_execution()

        self._require_rip(next_va)

        registers = self.debugger.get_registers(
            "rcx", "rsi", "rdi"
        )

        if registers["rcx"] != 0:
            raise RuntimeDecryptError(
                "REP MOVSQ did not complete"
            )

        if registers["rsi"] != source_va + copy_size:
            raise RuntimeDecryptError(
                "Unexpected final RSI"
            )

        if registers["rdi"] != destination_va + copy_size:
            raise RuntimeDecryptError(
                "Unexpected final RDI"
            )

        self.debugger.clear_all_breakpoints()

        print("[copy] Bulk copy completed")

    # ----------------------------------------------------------
    # Combined decryption and reconstruction monitoring
    # ----------------------------------------------------------

    def _observe_decryption_and_reconstruction(
        self,
        allocation: AllocationInfo,
        copy: CopyInfo,
        image_base: int,
        image_end: int,
    ) -> tuple[RecoveredPE, tuple[ProtectionEvent, ...]]:
        '''
        Begin monitoring immediately after REP MOVSQ.

        Monitor:
            - Original ciphertext source header writes
            - VirtualProtect calls
            - Candidate OEP execution

        The intermediate PE is parsed only within a bounded
        region of the known ciphertext source.

        VirtualProtect events provide reconstruction
        synchronization points.

        The final mapped image is checked at the OEP.
        '''

        source_va = copy.source_va
        source_size = copy.size

        recovered = self._parse_recovered_pe(
            source_va,
            source_size,
        )

        protection_events = []

        oep_va = None

        def install_monitor_breakpoints() -> None:
            self.debugger.clear_all_breakpoints()

            self._set_api_breakpoint("VirtualProtect")

            if recovered is None:
                self._set_source_breakpoint(source_va)

            if oep_va is not None:
                self._set_oep_breakpoint(oep_va)

        if recovered is not None:
            oep_va = image_base + recovered.oep_rva

        install_monitor_breakpoints()

        for event_number in range(self.max_monitor_events):
            output = self.debugger.continue_execution()

            event = self._classify_event(output)

            if event is None:
                raise RuntimeDecryptError(
                    "Unclassified reconstruction stop:\n"
                    + output[-1500:]
                )

            print(
                f"[monitor] Event {event_number + 1}: {event}"
            )

            if event == "OEP":
                if recovered is None or oep_va is None:
                    raise RuntimeDecryptError(
                        "OEP reached without recovered PE"
                    )

                self._require_rip(oep_va)

                self._validate_mapped_image(
                    image_base=image_base,
                    recovered=recovered,
                )

                self.debugger.clear_all_breakpoints()

                print(
                    f"[oep] Confirmed: 0x{oep_va:X}"
                )

                return recovered, tuple(protection_events)

            if event == "VirtualProtect":
                request = self._capture_virtual_protect()

                # Temporarily remove breakpoints so gu can
                # return from the API without interruption.
                self.debugger.clear_all_breakpoints()

                self.debugger.command(
                    "gu",
                    timeout=120.0,
                )

                self._require_rip(
                    request.return_address
                )

                succeeded = (
                    self.debugger.get_register("rax") != 0
                )

                completed = ProtectionEvent(
                    address=request.address,
                    size=request.size,
                    new_protection=request.new_protection,
                    return_address=request.return_address,
                    succeeded=succeeded,
                )

                protection_events.append(completed)

                if succeeded:
                    print(
                        "[protect] "
                        f"0x{completed.address:X} "
                        f"size=0x{completed.size:X} "
                        f"protect=0x{completed.new_protection:X}"
                    )

                # This API return is also a synchronization
                # point for inspecting the ciphertext source.
                if recovered is None:
                    recovered = self._parse_recovered_pe(
                        source_va,
                        source_size,
                    )

                if recovered is not None and oep_va is None:
                    oep_va = image_base + recovered.oep_rva

                    if not (
                        image_base <= oep_va < image_end
                    ):
                        raise RuntimeDecryptError(
                            "Candidate OEP outside main image"
                        )

                    print(
                        f"[decrypt] PE: 0x{recovered.buffer_va:X}"
                    )
                    print(
                        f"[decrypt] OEP RVA: 0x{recovered.oep_rva:X}"
                    )

                install_monitor_breakpoints()
                continue

            if event == "SourceWrite":
                if recovered is None:
                    recovered = self._parse_recovered_pe(
                        source_va,
                        source_size,
                    )

                if recovered is not None and oep_va is None:
                    oep_va = image_base + recovered.oep_rva

                    if not (
                        image_base <= oep_va < image_end
                    ):
                        raise RuntimeDecryptError(
                            "Candidate OEP outside main image"
                        )

                    print(
                        f"[decrypt] Recovered PE: "
                        f"0x{recovered.buffer_va:X}"
                    )

                    print(
                        f"[decrypt] OEP RVA: "
                        f"0x{recovered.oep_rva:X}"
                    )

                    install_monitor_breakpoints()

                continue

            raise RuntimeDecryptError(
                f"Unexpected monitoring event: {event}"
            )

        raise RuntimeDecryptError(
            "OEP not reached within monitoring event limit"
        )

    # ----------------------------------------------------------
    # VirtualProtect handling
    # ----------------------------------------------------------

    def _capture_virtual_protect(
        self,
    ) -> ProtectionEvent:
        '''
        Windows x64 VirtualProtect arguments:

            RCX = lpAddress
            RDX = dwSize
            R8  = flNewProtect
            R9  = lpflOldProtect

        RAX is inspected separately after returning.
        '''

        registers = self.debugger.get_registers(
            "rcx", "rdx", "r8", "rsp"
        )

        return ProtectionEvent(
            address=registers["rcx"],
            size=registers["rdx"],
            new_protection=registers["r8"],
            return_address=self.debugger.read_qword(
                registers["rsp"]
            ),
        )

    def _protection_overlaps_image(
        self,
        event: ProtectionEvent,
        image_base: int,
        image_size: int,
    ) -> bool:
        image_end = image_base + image_size

        protection_end = (
            event.address + event.size
        )

        return (
            event.address < image_end
            and protection_end > image_base
        )

    # ----------------------------------------------------------
    # PE header recovery
    # ----------------------------------------------------------

    def _parse_recovered_pe(
        self,
        source_va: int,
        source_size: int,
    ) -> RecoveredPE | None:
        '''
        Parse a recovered PE near the beginning of the known
        ciphertext source region.

        A small offset is permitted because the observed
        ransomware sample places MZ at source + 0x4.

        This is not an unrestricted memory scan.
        '''

        header_size = min(source_size, 0x2000)

        if header_size < 0x200:
            return None

        with TemporaryDirectory() as directory:
            path = Path(directory) / "headers.bin"

            self.debugger.write_memory(
                output_path=path,
                start_va=source_va,
                end_va=source_va + header_size,
            )

            data = path.read_bytes()

        pe_offset = self._find_recovered_pe_offset(
            data
        )

        if pe_offset is None:
            return None

        recovered_pe_va = source_va + pe_offset

        data = data[pe_offset:]

        e_lfanew = struct.unpack_from(
            "<I", data, 0x3C
        )[0]

        if e_lfanew + 0x18 > len(data):
            return None

        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None

        optional_offset = e_lfanew + 0x18

        if optional_offset + 0x40 > len(data):
            return None

        magic = struct.unpack_from(
            "<H", data, optional_offset
        )[0]

        if magic != 0x20B:
            return None

        number_of_sections = struct.unpack_from(
            "<H", data, e_lfanew + 6
        )[0]

        optional_size = struct.unpack_from(
            "<H", data, e_lfanew + 20
        )[0]

        oep_rva = struct.unpack_from(
            "<I", data, optional_offset + 0x10
        )[0]

        preferred_base = struct.unpack_from(
            "<Q", data, optional_offset + 0x18
        )[0]

        image_size = struct.unpack_from(
            "<I", data, optional_offset + 0x38
        )[0]

        section_table = (
            optional_offset + optional_size
        )

        if not (0 < number_of_sections <= 96):
            return None

        if not (0 < oep_rva < image_size):
            return None

        if (
            section_table + number_of_sections * 40
            > len(data)
        ):
            return None

        sections = []

        for index in range(number_of_sections):
            offset = section_table + index * 40

            name = (
                data[offset:offset + 8]
                .rstrip(b"\x00")
                .decode("ascii", errors="replace")
            )

            virtual_size, rva, raw_size, raw_offset = (
                struct.unpack_from(
                    "<IIII",
                    data,
                    offset + 8,
                )
            )

            characteristics = struct.unpack_from(
                "<I",
                data,
                offset + 36,
            )[0]

            if rva >= image_size:
                return None

            if (
                rva + max(virtual_size, raw_size)
                > image_size
            ):
                return None

            sections.append(
                RecoveredSection(
                    name=name,
                    rva=rva,
                    virtual_size=virtual_size,
                    raw_size=raw_size,
                    raw_offset=raw_offset,
                    characteristics=characteristics,
                )
            )

        oep_valid = any(
            section.executable
            and section.rva <= oep_rva
            < section.rva + max(
                section.virtual_size,
                section.raw_size,
            )
            for section in sections
        )

        if not oep_valid:
            return None

        return RecoveredPE(
            buffer_va=recovered_pe_va,
            preferred_image_base=preferred_base,
            image_size=image_size,
            oep_rva=oep_rva,
            sections=tuple(sections),
        )

    def _find_recovered_pe_offset(
        self,
        data: bytes,
    ) -> int | None:
        '''
        Identify a valid DOS/NT header within the first
        max_header_offset bytes of the known source.
        '''

        max_offset = min(
            self.max_header_offset,
            len(data) - 0x200,
        )

        for offset in range(max_offset + 1):
            if data[offset:offset + 2] != b"MZ":
                continue

            e_lfanew = struct.unpack_from(
                "<I",
                data,
                offset + 0x3C,
            )[0]

            nt_offset = offset + e_lfanew

            if nt_offset + 0x18 > len(data):
                continue

            if (
                data[nt_offset:nt_offset + 4]
                != b"PE\x00\x00"
            ):
                continue

            return offset

        return None

    # ----------------------------------------------------------
    # Final mapped-image validation
    # ----------------------------------------------------------

    def _validate_mapped_image(
        self,
        image_base: int,
        recovered: RecoveredPE,
    ) -> None:
        '''
        Validate that execution reached the candidate OEP
        and that the mapped image contains compatible PE
        metadata.

        This is a structural check, not a full comparison
        of every recovered section byte.
        '''

        mapped = self._parse_recovered_pe(
            source_va=image_base,
            source_size=min(
                recovered.image_size,
                0x2000,
            ),
        )

        if mapped is None:
            raise RuntimeDecryptError(
                "Mapped image PE headers not validated"
            )

        if mapped.oep_rva != recovered.oep_rva:
            raise RuntimeDecryptError(
                "Mapped image OEP differs from recovered PE"
            )

        if mapped.image_size != recovered.image_size:
            raise RuntimeDecryptError(
                "Mapped image size differs from recovered PE"
            )

        print("[validate] Mapped PE headers verified")

    # ----------------------------------------------------------
    # Validation helpers
    # ----------------------------------------------------------

    def _require_rip(self, expected_va: int) -> None:
        actual_va = self.debugger.get_register("rip")

        if actual_va != expected_va:
            raise RuntimeDecryptError(
                f"Unexpected RIP: "
                f"expected 0x{expected_va:X}, "
                f"got 0x{actual_va:X}"
            )