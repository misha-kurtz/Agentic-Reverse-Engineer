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
        max_copy_instructions=4096,
        max_monitor_events: int=10000,
        max_header_offset: int = 0x40,
    ):
        self.debugger = debugger

        self.max_bootstrap_events = max_bootstrap_events
        self.max_copy_instructions = max_copy_instructions
        self.max_monitor_events = max_monitor_events
        self.max_header_offset = max_header_offset

        self._previous_header_bytes = None

    # ----------------------------------------------------------
    # Public workflow
    # ----------------------------------------------------------

    def run(self, executable: Path | str) -> DecryptResult:
        '''
        Execute the Hyperion runtime recovery workflow.

        Workflow:

            1. Launch the encrypted executable.
            2. Stop at the encrypted entry point.
            3. Observe loader bootstrap and VirtualAlloc.
            4. Identify the ciphertext REP MOVSQ operation.
            5. Stop immediately after REP MOVSQ completes.
            6. Monitor the temporary allocation for clearing.
            7. Monitor reconstruction of the original PE.
            8. Identify and validate the recovered OEP.
        '''

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

            print(
                f"[hyperion] Image base: 0x{image_base:X}"
            )

            print(
                f"[hyperion] Entry VA: 0x{entry_va:X}"
            )

            # --------------------------------------------------
            # Stage 1: Stop at encrypted entry point
            # --------------------------------------------------

            self.debugger.set_breakpoint(entry_va)

            self.debugger.continue_execution()

            self._require_rip(entry_va)

            self.debugger.clear_all_breakpoints()

            # --------------------------------------------------
            # Stage 2: Observe loader bootstrap
            # --------------------------------------------------

            bootstrap_events, allocation = (
                self._observe_loader_bootstrap(
                    image_base=image_base,
                    image_end=module.end,
                )
            )

            # --------------------------------------------------
            # Stage 3: Identify and complete REP MOVSQ
            # --------------------------------------------------

            copy = self._observe_bulk_copy(allocation)

            print(
                "\n[hyperion] Initial ciphertext copy completed."
            )

            print(
                f"[hyperion] Source: "
                f"0x{copy.source_va:X}"
            )

            print(
                f"[hyperion] Temporary allocation: "
                f"0x{allocation.base:X}"
            )

            # --------------------------------------------------
            # Stage 4: Wait for temporary allocation clearing
            # --------------------------------------------------

            print(
                "\n[hyperion] Monitoring temporary allocation "
                "for post-copy modifications."
            )

            self._wait_for_allocation_clear(
                allocation=allocation,
                copy=copy,
            )

            print(
                "\n[hyperion] Temporary allocation transition "
                "detected."
            )

            # --------------------------------------------------
            # Stage 5: Monitor recovered PE reconstruction
            # --------------------------------------------------

            recovered, protection_events = (
                self._observe_decryption_and_reconstruction(
                    allocation=allocation,
                    copy=copy,
                    image_base=image_base,
                    image_end=module.end,
                )
            )

            # --------------------------------------------------
            # Stage 6: Calculate recovered OEP
            # --------------------------------------------------

            oep_va = image_base + recovered.oep_rva

            print(
                "\n[hyperion] Recovered PE identified."
            )

            print(
                f"[hyperion] Recovered PE VA: "
                f"0x{recovered.buffer_va:X}"
            )

            print(
                f"[hyperion] OEP RVA: "
                f"0x{recovered.oep_rva:X}"
            )

            print(
                f"[hyperion] OEP VA: "
                f"0x{oep_va:X}"
            )

            # --------------------------------------------------
            # Stage 7: Return recovery result
            # --------------------------------------------------

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
                    rip=rip,
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

            self.debugger.command("gu", timeout=120.0)

            return_rip = self.debugger.get_register("rip")

            print(
                f"[allocation] Expected return RIP: "
                f"0x{return_address:X}"
            )

            print(
                f"[allocation] Actual return RIP:   "
                f"0x{return_rip:X}"
            )

            if return_rip != return_address:
                raise RuntimeDecryptError(
                    "VirtualAlloc did not return to the expected caller. "
                    f"Expected 0x{return_address:X}, "
                    f"got 0x{return_rip:X}"
                )

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

        Identify the REP MOVSQ instruction using its machine-code
        encoding rather than relying exclusively on debugger
        disassembly formatting.

        Validate:
            - destination matches the observed allocation
            - copy size matches the allocation size
            - source and destination are nonzero

        Once identified, stop immediately after the copy and
        validate the resulting register state.
        '''

        for instruction_index in range(
            self.max_copy_instructions
        ):
            rip = self.debugger.get_register("rip")

            instruction = self.debugger.disassemble_one(rip)

            mnemonic = instruction.mnemonic.lower()
            operands = instruction.operands.lower()

            raw_bytes = instruction.raw_bytes

            # REP MOVSQ:
            #
            # F3 = REP
            # 48 = REX.W
            # A5 = MOVS
            #
            # The debugger may display this as:
            #
            #   rep movs qword ptr [rdi], qword ptr [rsi]
            #
            # rather than:
            #
            #   rep movsq

            is_rep_movsq = (
                raw_bytes.startswith(b"\xF3\x48\xA5")
                or raw_bytes.startswith(b"\x48\xF3\xA5")
            )

            if instruction_index < 30:
                print(
                    f"[copy-trace] "
                    f"{instruction_index:04d} "
                    f"0x{rip:X}: "
                    f"{mnemonic} {operands} "
                    f"bytes={raw_bytes.hex()}"
                )

            if not is_rep_movsq:
                self.debugger.command("p")
                continue

            print(
                f"\n[copy] REP MOVSQ detected at 0x{rip:X}"
            )

            registers = self.debugger.get_registers(
                "rsi",
                "rdi",
                "rcx",
            )

            source_va = registers["rsi"]
            destination_va = registers["rdi"]
            copy_size = registers["rcx"] * 8

            print(
                "\n[copy] Candidate details:\n"
                f"  Instruction:  0x{rip:X}\n"
                f"  Source:       0x{source_va:X}\n"
                f"  Destination:  0x{destination_va:X}\n"
                f"  RCX:          0x{registers['rcx']:X}\n"
                f"  Copy size:    0x{copy_size:X}\n"
                f"  Alloc base:   0x{allocation.base:X}\n"
                f"  Alloc size:   0x{allocation.size:X}"
            )

            if destination_va != allocation.base:
                print(
                    "[copy] Candidate rejected: "
                    "destination does not match allocation."
                )

                self.debugger.command("p")
                continue

            if copy_size != allocation.size:
                print(
                    "[copy] Candidate rejected: "
                    "copy size does not match allocation."
                )

                self.debugger.command("p")
                continue

            if source_va == 0 or destination_va == 0:
                raise RuntimeDecryptError(
                    "REP MOVSQ has an invalid source or destination."
                )

            print(
                "\n[copy] Matching REP MOVSQ confirmed."
            )

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
            "Matching REP MOVSQ not found within "
            f"{self.max_copy_instructions} instructions."
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

    def _wait_for_allocation_clear(
        self,
        allocation: AllocationInfo,
        copy: CopyInfo,
    ) -> None:
        '''
        Wait for a write to the temporary allocation after the
        initial REP MOVSQ ciphertext copy has completed.

        Reproduce the manual x64dbg workflow:

            1. Stop at the instruction after REP MOVSQ.
            2. Confirm the allocation contains copied ciphertext.
            3. Install a write breakpoint on the allocation.
            4. Continue execution.
            5. Detect when the monitored bytes become zero.
            6. Return so PE reconstruction monitoring can begin.

        The breakpoint monitors the first eight bytes of the
        allocation, not the entire allocation.
        '''

        if allocation.base == 0:
            raise RuntimeDecryptError(
                "Cannot monitor an invalid allocation address."
            )

        if allocation.size < 8:
            raise RuntimeDecryptError(
                "Allocation is too small for an eight-byte watchpoint."
            )

        if copy.destination_va != allocation.base:
            raise RuntimeDecryptError(
                "Copy destination does not match the allocation base."
            )

        watch_va = allocation.base

        sample_size = min(allocation.size, 64)

        def read_allocation_sample() -> bytes:
            '''
            Read the beginning of the temporary allocation.
            '''

            with TemporaryDirectory() as directory:

                path = Path(directory) / "allocation_sample.bin"

                self.debugger.write_memory(
                    output_path=path,
                    start_va=allocation.base,
                    end_va=allocation.base + sample_size,
                )

                data = path.read_bytes()

            if len(data) != sample_size:
                raise RuntimeDecryptError(
                    "Failed to read the expected allocation sample. "
                    f"Expected {sample_size} bytes, got {len(data)}."
                )

            recovered = self._parse_recovered_pe(
                copy.source_va,
                copy.size,
            )

            if recovered is not None:

                print(
                    "[allocation-monitor] Recovered PE detected "
                    "immediately after allocation clearing."
                )

                print(
                    f"[allocation-monitor] PE VA: "
                    f"0x{recovered.buffer_va:X}"
                )

                print(
                    f"[allocation-monitor] OEP RVA: "
                    f"0x{recovered.oep_rva:X}"
                )

            else:

                print(
                    "[allocation-monitor] Allocation cleared, "
                    "but a valid recovered PE was not detected yet."
                )

            return data

        # --------------------------------------------------
        # Step 1: Capture allocation contents after REP MOVSQ
        # --------------------------------------------------

        print(
            "\n[allocation-monitor] Initial ciphertext copy completed."
        )

        print(
            f"[allocation-monitor] Allocation base: "
            f"0x{allocation.base:X}"
        )

        print(
            f"[allocation-monitor] Allocation size: "
            f"0x{allocation.size:X}"
        )

        initial_sample = read_allocation_sample()

        print(
            "[allocation-monitor] Initial allocation bytes:\n"
            f"  {initial_sample.hex(' ')}"
        )

        if not any(initial_sample):
            raise RuntimeDecryptError(
                "Temporary allocation is already zero at the "
                "post-REP MOVSQ checkpoint."
            )

        # --------------------------------------------------
        # Step 2: Install write breakpoint
        # --------------------------------------------------

        self.debugger.clear_all_breakpoints()

        breakpoint_output = self.debugger.command(
            f"ba w8 0x{watch_va:X}"
        )

        if (
            "error" in breakpoint_output.lower()
            or "couldn't" in breakpoint_output.lower()
        ):
            raise RuntimeDecryptError(
                "Failed to install allocation write breakpoint:\n"
                f"{breakpoint_output}"
            )

        print(
            "[allocation-monitor] Write breakpoint installed:\n"
            f"  Address: 0x{watch_va:X}\n"
            "  Size:    8 bytes"
        )

        # --------------------------------------------------
        # Step 3: Wait for the allocation to change
        # --------------------------------------------------

        previous_sample = initial_sample

        try:

            for event_number in range(self.max_monitor_events):

                self.debugger.continue_execution()

                rip = self.debugger.get_register("rip")

                current_sample = read_allocation_sample()

                if current_sample != previous_sample:

                    changed_offsets = [
                        index
                        for index, (old, new) in enumerate(
                            zip(previous_sample, current_sample)
                        )
                        if old != new
                    ]

                    print(
                        "\n[allocation-monitor] Allocation modified."
                    )

                    print(
                        f"[allocation-monitor] Event: "
                        f"{event_number + 1}"
                    )

                    print(
                        f"[allocation-monitor] RIP: 0x{rip:X}"
                    )

                    print(
                        "[allocation-monitor] Changed offsets: "
                        + ", ".join(
                            f"0x{offset:X}"
                            for offset in changed_offsets
                        )
                    )

                    print(
                        "[allocation-monitor] Current bytes:\n"
                        f"  {current_sample.hex(' ')}"
                    )

                # --------------------------------------------------
                # Step 4: Detect the zeroed allocation
                # --------------------------------------------------

                if not any(current_sample):

                    print(
                        "\n[allocation-monitor] Allocation sample "
                        "is now zero."
                    )

                    print(
                        f"[allocation-monitor] Event: "
                        f"{event_number + 1}"
                    )

                    print(
                        f"[allocation-monitor] RIP: 0x{rip:X}"
                    )

                    print(
                        "[allocation-monitor] Temporary allocation "
                        "transition detected."
                    )

                    return

                previous_sample = current_sample

            raise RuntimeDecryptError(
                "Temporary allocation did not become zero within "
                f"{self.max_monitor_events} write-breakpoint events."
            )

        finally:

            self.debugger.clear_all_breakpoints()

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

        Track whether VirtualProtect modifies the recovered
        OEP region and whether the requested protection
        permits execution.

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

        executable_protections = {
            0x10,  # PAGE_EXECUTE
            0x20,  # PAGE_EXECUTE_READ
            0x40,  # PAGE_EXECUTE_READWRITE
            0x80,  # PAGE_EXECUTE_WRITECOPY
        }

        def install_monitor_breakpoints() -> None:
            '''
            Install monitoring breakpoints based on the
            current recovery state.
            '''

            self.debugger.clear_all_breakpoints()

            self._set_api_breakpoint("VirtualProtect")

            if recovered is None:
                self._set_source_breakpoint(source_va)

            if oep_va is not None:
                self._set_oep_breakpoint(oep_va)

        if recovered is not None:
            oep_va = image_base + recovered.oep_rva

            if not (
                image_base <= oep_va < image_end
            ):
                raise RuntimeDecryptError(
                    "Candidate OEP outside main image"
                )

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

            # --------------------------------------------------
            # OEP execution confirmation
            # --------------------------------------------------

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

            # --------------------------------------------------
            # VirtualProtect monitoring
            # --------------------------------------------------

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

                # VirtualProtect returning is also a
                # synchronization point for inspecting
                # the ciphertext source.
                if recovered is None:

                    recovered = self._parse_recovered_pe(
                        source_va,
                        source_size,
                    )

                # Initialize the OEP once the recovered
                # PE headers have passed validation.
                if recovered is not None and oep_va is None:

                    oep_va = image_base + recovered.oep_rva

                    if not (
                        image_base <= oep_va < image_end
                    ):
                        raise RuntimeDecryptError(
                            "Candidate OEP outside main image"
                        )

                    print(
                        f"[decrypt] PE: "
                        f"0x{recovered.buffer_va:X}"
                    )

                    print(
                        f"[decrypt] OEP RVA: "
                        f"0x{recovered.oep_rva:X}"
                    )

                    print(
                        f"[decrypt] OEP VA: "
                        f"0x{oep_va:X}"
                    )

                # Determine whether this completed
                # VirtualProtect call affected the OEP.
                if recovered is not None and oep_va is not None:

                    oep_protection_changed = (
                        completed.succeeded
                        and completed.address <= oep_va
                        < completed.address + completed.size
                    )

                    if oep_protection_changed:

                        protection_base = (
                            completed.new_protection & 0xFF
                        )

                        is_executable = (
                            protection_base
                            in executable_protections
                        )

                        print(
                            "[protect] OEP region modified:\n"
                            f"  OEP VA:         0x{oep_va:X}\n"
                            f"  Region base:    "
                            f"0x{completed.address:X}\n"
                            f"  Region size:    "
                            f"0x{completed.size:X}\n"
                            f"  New protection: "
                            f"0x{completed.new_protection:X}\n"
                            f"  Executable:     {is_executable}"
                        )

                install_monitor_breakpoints()
                continue

            # --------------------------------------------------
            # Ciphertext source write monitoring
            # --------------------------------------------------

            if event == "SourceWrite":

                # Report the first ten source-write events,
                # then periodically report execution progress.
                if (
                    event_number < 10
                    or event_number % 100 == 0
                ):

                    rip = self.debugger.get_register("rip")

                    instruction = (
                        self.debugger.disassemble_one(rip)
                    )

                    print(
                        f"[source-write] "
                        f"Event={event_number + 1} "
                        f"RIP=0x{rip:X} "
                        f"{instruction.mnemonic} "
                        f"{instruction.operands}"
                    )

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

                    print(
                        f"[decrypt] OEP VA: "
                        f"0x{oep_va:X}"
                    )

                    # Remove the source-write breakpoint
                    # and install the OEP breakpoint.
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

        Validate the PE structure without requiring the OEP
        section to be marked executable.

        Runtime execution permissions are monitored separately
        through VirtualProtect events.
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

            # Capture the first 64 bytes of the source region.
            current_header_bytes = data[:64]

            # Only print when the bytes differ from the previous snapshot.
            if current_header_bytes != self._previous_header_bytes:

                if self._previous_header_bytes is None:
                    print("[pe-debug] Initial header snapshot")

                else:
                    print("[pe-debug] Header bytes changed")

                    # Identify which byte offsets changed.
                    changed_offsets = [
                        index
                        for index, (old, new) in enumerate(
                            zip(
                                self._previous_header_bytes,
                                current_header_bytes,
                            )
                        )
                        if old != new
                    ]

                    print(
                        "[pe-debug] Changed offsets: "
                        + ", ".join(
                            f"0x{offset:X}"
                            for offset in changed_offsets
                        )
                    )

                print(
                    f"[pe-debug] Source VA: 0x{source_va:X}"
                )

                print(
                    "[pe-debug] Header bytes: "
                    f"{current_header_bytes.hex(' ')}"
                )

                # Save this snapshot for the next comparison.
                self._previous_header_bytes = current_header_bytes
        # --------------------------------------------------
        # Detect candidate DOS headers
        # --------------------------------------------------

        candidate_offsets = [
            offset
            for offset in range(
                min(
                    self.max_header_offset + 1,
                    max(0, len(data) - 1),
                )
            )
            if data[offset:offset + 2] == b"MZ"
        ]

        if candidate_offsets:

            print(
                "[pe-debug] MZ candidate(s): "
                + ", ".join(
                    f"0x{offset:X}"
                    for offset in candidate_offsets
                )
            )

            print(
                "[pe-debug] First 64 bytes: "
                f"{data[:64].hex(' ')}"
            )

        # --------------------------------------------------
        # Locate a valid DOS/NT header
        # --------------------------------------------------

        pe_offset = self._find_recovered_pe_offset(
            data
        )

        if pe_offset is None:
            return None

        print(
            "[pe-debug] Valid DOS/NT header "
            f"at offset 0x{pe_offset:X}"
        )

        recovered_pe_va = source_va + pe_offset

        data = data[pe_offset:]

        # --------------------------------------------------
        # Parse DOS header
        # --------------------------------------------------

        e_lfanew = struct.unpack_from(
            "<I",
            data,
            0x3C,
        )[0]

        if e_lfanew + 0x18 > len(data):
            return None

        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None

        # --------------------------------------------------
        # Parse NT headers
        # --------------------------------------------------

        optional_offset = e_lfanew + 0x18

        if optional_offset + 0x40 > len(data):
            return None

        magic = struct.unpack_from(
            "<H",
            data,
            optional_offset,
        )[0]

        if magic != 0x20B:
            return None

        number_of_sections = struct.unpack_from(
            "<H",
            data,
            e_lfanew + 6,
        )[0]

        optional_size = struct.unpack_from(
            "<H",
            data,
            e_lfanew + 20,
        )[0]

        oep_rva = struct.unpack_from(
            "<I",
            data,
            optional_offset + 0x10,
        )[0]

        preferred_base = struct.unpack_from(
            "<Q",
            data,
            optional_offset + 0x18,
        )[0]

        image_size = struct.unpack_from(
            "<I",
            data,
            optional_offset + 0x38,
        )[0]

        section_table = (
            optional_offset + optional_size
        )

        # --------------------------------------------------
        # Validate PE metadata
        # --------------------------------------------------

        if not (0 < number_of_sections <= 96):
            return None

        if not (0 < oep_rva < image_size):
            return None

        if (
            section_table + number_of_sections * 40
            > len(data)
        ):
            return None

        # --------------------------------------------------
        # Parse section headers
        # --------------------------------------------------

        sections = []

        for index in range(number_of_sections):

            offset = section_table + index * 40

            name = (
                data[offset:offset + 8]
                .rstrip(b"\x00")
                .decode(
                    "ascii",
                    errors="replace",
                )
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

        # --------------------------------------------------
        # Validate OEP section membership
        # --------------------------------------------------

        oep_section = next(
            (
                section
                for section in sections
                if section.rva <= oep_rva
                < section.rva + max(
                    section.virtual_size,
                    section.raw_size,
                )
            ),
            None,
        )

        if oep_section is None:
            return None

        print(
            f"[pe] OEP RVA: 0x{oep_rva:X}\n"
            f"[pe] OEP section: {oep_section.name}\n"
            f"[pe] Section characteristics: "
            f"0x{oep_section.characteristics:X}\n"
            f"[pe] Section marked executable: "
            f"{oep_section.executable}"
        )

        # --------------------------------------------------
        # Return recovered PE metadata
        # --------------------------------------------------

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