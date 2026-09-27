# binary-eval/runners/iat.py 

'''
Import Address Table Reconstruction

debugger.py
    ↓
OEP + module map

iat.py
    ├── discover candidate IAT ranges
    ├── read thunk values
    ├── resolve target modules
    ├── score candidate
    └── prune invalid thunks

pe_sieve.py / reconstruction.py
    ↓
actually rebuild PE
'''

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Protocol
from runners.debugger import ModuleInfo


# ----------------------------------------------------------------------
# Exceptions
# ----------------------------------------------------------------------


class IATError(RuntimeError):
    pass


# ----------------------------------------------------------------------
# Debugger interface
# ----------------------------------------------------------------------


class MemoryReader(Protocol):
    """
    Minimal memory-reading interface required by IATAnalyzer.

    Implementations may use CDB, DbgEng, another debugger,
    or any other mechanism capable of reading live process memory.
    """

    def read_qword(
        self,
        address: int,
    ) -> int:
        """
        Read one 64-bit little-endian value from process memory.
        """
        ...

    def read_qwords(
        self,
        address: int,
        count: int,
    ) -> tuple[int, ...]:
        """
        Read `count` contiguous 64-bit values beginning at `address`.

        Values are returned in increasing memory-address order.
        """
        ...


# ----------------------------------------------------------------------
# Data models
# ----------------------------------------------------------------------


class ThunkStatus(str, Enum):
    """
    Classification of the resolved address stored in an IAT slot.
    """

    VALID_EXTERNAL = "valid_external"

    # Target points back into the executable image itself.
    # For a resolved import thunk, this is generally suspicious.
    INVALID_INTERNAL = "invalid_internal"

    # Nonzero target that does not belong to any known loaded module.
    UNRESOLVED = "unresolved"

    # Empty slot.
    NULL = "null"


@dataclass(frozen=True)
class ModuleRange:
    """
    Runtime VA range occupied by one loaded module.
    """

    name: str
    base: int
    end: int

    def contains(
        self,
        address: int,
    ) -> bool:

        return (
            self.base
            <= address
            < self.end
        )

    @property
    def size(self) -> int:
        return self.end - self.base


@dataclass(frozen=True)
class Thunk:
    """
    One candidate IAT slot.

    slot_va:
        Address of the IAT slot inside the analyzed image.

    target_va:
        Runtime address currently stored in that slot.

    status:
        Classification of target_va.

    target_module:
        Module containing target_va, if resolved.
    """

    slot_va: int
    target_va: int
    status: ThunkStatus
    target_module: str | None = None


@dataclass(frozen=True)
class IATCandidate:
    """
    One candidate IAT range, such as a Scylla-like Normal or Advanced
    search result.
    """

    name: str
    start_va: int
    size: int
    thunks: tuple[Thunk, ...]

    @property
    def end_va(self) -> int:
        return self.start_va + self.size

    @property
    def total(self) -> int:
        return len(self.thunks)

    @property
    def valid_external(self) -> int:
        return sum(
            thunk.status
            == ThunkStatus.VALID_EXTERNAL
            for thunk in self.thunks
        )

    @property
    def invalid_internal(self) -> int:
        return sum(
            thunk.status
            == ThunkStatus.INVALID_INTERNAL
            for thunk in self.thunks
        )

    @property
    def unresolved(self) -> int:
        return sum(
            thunk.status
            == ThunkStatus.UNRESOLVED
            for thunk in self.thunks
        )

    @property
    def null_entries(self) -> int:
        return sum(
            thunk.status
            == ThunkStatus.NULL
            for thunk in self.thunks
        )

    @property
    def invalid_total(self) -> int:
        """
        Entries we would not currently retain during reconstruction.
        """

        return (
            self.invalid_internal
            + self.unresolved
        )

    @property
    def valid_thunks(self) -> tuple[Thunk, ...]:
        return tuple(
            thunk
            for thunk in self.thunks
            if (
                thunk.status
                == ThunkStatus.VALID_EXTERNAL
            )
        )

    @property
    def non_null_total(self) -> int:
        return (
            self.total
            - self.null_entries
        )


    @property
    def valid_density(self) -> float:
        """
        Fraction of the entire candidate range containing
        valid external import targets.
        """

        if self.total == 0:
            return 0.0

        return (
            self.valid_external
            / self.total
        )


    @property
    def invalid_density(self) -> float:
        """
        Fraction of non-null entries that are invalid or unresolved.
        """

        if self.non_null_total == 0:
            return 0.0

        return (
            self.invalid_total
            / self.non_null_total
        )

@dataclass(frozen=True)
class IATRange:
    name: str
    start_va: int
    size: int

    @property
    def end_va(self) -> int:
        return (
            self.start_va
            + self.size
        )


@dataclass(frozen=True)
class IATAnalysisResult:
    """
    Result of comparing one or more candidate IAT ranges.
    """

    candidates: tuple[IATCandidate, ...]
    selected: IATCandidate

    @property
    def valid_thunks(self) -> tuple[Thunk, ...]:
        return self.selected.valid_thunks


# ----------------------------------------------------------------------
# Analyzer
# ----------------------------------------------------------------------


class IATAnalyzer:
    """
    Discover, analyze, and select candidate Import Address Table ranges.

    Deterministic strategy:

        1. Scan the reconstructed image for pointer-sized values.
        2. Classify pointer targets using the loaded-module map.
        3. Identify strict clusters of externally resolved pointers.
        4. Construct conservative expanded candidates across
           small invalid/unresolved gaps.
        5. Analyze and score candidate ranges.
        6. Select the strongest candidate.
        7. Return externally resolved thunks for reconstruction.
    """

    def __init__(
        self,
        debugger: MemoryReader,
        image_start: int,
        image_end: int,
        modules: Iterable[ModuleInfo],
        pointer_size: int = 8,
    ):
        if image_end <= image_start:
            raise ValueError(
                "image_end must be greater than image_start"
            )

        if pointer_size not in (4, 8):
            raise ValueError(
                "pointer_size must be 4 or 8"
            )

        self.debugger = debugger
        self.image_start = image_start
        self.image_end = image_end
        self.modules = tuple(modules)
        self.pointer_size = pointer_size

    # ------------------------------------------------------------------
    # Target classification
    # ------------------------------------------------------------------

    def classify_target(
        self,
        target_va: int,
    ) -> tuple[ThunkStatus, str | None]:

        if target_va == 0:
            return (
                ThunkStatus.NULL,
                None,
            )

        #
        # A resolved import thunk normally points into another loaded
        # module rather than back into the executable image being
        # reconstructed.
        #
        if (
            self.image_start
            <= target_va
            < self.image_end
        ):
            return (
                ThunkStatus.INVALID_INTERNAL,
                None,
            )

        #
        # Strong validation:
        # the target must fall inside a known loaded module.
        #
        module = self.resolve_target_module(
            target_va
        )

        if module is not None:
            return (
                ThunkStatus.VALID_EXTERNAL,
                module.name,
            )

        return (
            ThunkStatus.UNRESOLVED,
            None,
        )

    def resolve_target_module(
        self,
        target_va: int,
    ) -> ModuleInfo | None:

        for module in self.modules:
            if (
                module.base
                <= target_va
                < module.end
            ):
                return module

        return None

    # ------------------------------------------------------------------
    # Candidate analysis
    # ------------------------------------------------------------------

    def analyze_candidate(
        self,
        name: str,
        start_va: int,
        size: int,
    ) -> IATCandidate:

        if size <= 0:
            raise ValueError(
                "IAT candidate size must be positive"
            )

        if start_va <= 0:
            raise ValueError(
                "IAT candidate start address must be positive"
            )

        if size % self.pointer_size != 0:
            raise ValueError(
                f"IAT candidate size 0x{size:x} "
                f"is not aligned to pointer size "
                f"{self.pointer_size}"
            )

        thunks: list[Thunk] = []

        for offset in range(
            0,
            size,
            self.pointer_size,
        ):
            slot_va = (
                start_va
                + offset
            )

            try:
                target_va = (
                    self._read_pointer(
                        slot_va
                    )
                )
            except Exception as exc:
                raise IATError(
                    "Failed reading candidate IAT slot "
                    f"0x{slot_va:x}"
                ) from exc

            status, module_name = (
                self.classify_target(
                    target_va
                )
            )

            thunks.append(
                Thunk(
                    slot_va=slot_va,
                    target_va=target_va,
                    status=status,
                    target_module=module_name,
                )
            )

        return IATCandidate(
            name=name,
            start_va=start_va,
            size=size,
            thunks=tuple(thunks),
        )

    def analyze_candidates(
        self,
        candidates: Iterable[
            tuple[str, int, int]
        ],
    ) -> IATAnalysisResult:
        """
        Convenience wrapper.

        candidates:
            Iterable of:
                (name, start_va, size)

        Example:

            [
                ("normal",   0x..., 0x2F0),
                ("advanced", 0x..., 0x388),
            ]
        """

        analyzed: list[IATCandidate] = []

        for name, start_va, size in candidates:
            analyzed.append(
                self.analyze_candidate(
                    name=name,
                    start_va=start_va,
                    size=size,
                )
            )

        if not analyzed:
            raise IATError(
                "No IAT candidates were supplied"
            )

        selected = self.select_best(
            analyzed
        )

        return IATAnalysisResult(
            candidates=tuple(analyzed),
            selected=selected,
        )

    # ------------------------------------------------------------------
    # Candidate scoring
    # ------------------------------------------------------------------

    @staticmethod
    def score(
        candidate: IATCandidate,
    ) -> tuple[int, float, int, int, int]:
        """
        Lower tuple wins.

        Candidates have already passed structural discovery.

        Prefer:
            1. More valid external imports.
            2. Lower invalid density.
            3. Fewer invalid entries.
            4. Higher overall valid density.
            5. Smaller range.
        """

        return (
            -candidate.valid_external,
            candidate.invalid_density,
            candidate.invalid_total,
            -candidate.valid_density,
            candidate.size,
        )

    def select_best(
        self,
        candidates: Iterable[IATCandidate],
    ) -> IATCandidate:

        candidates = tuple(candidates)

        if not candidates:
            raise IATError(
                "No analyzed IAT candidates supplied"
            )

        return min(
            candidates,
            key=self.score,
        )

    # ------------------------------------------------------------------
    # Pruning
    # ------------------------------------------------------------------

    @staticmethod
    def prune_invalid_thunks(
        candidate: IATCandidate,
    ) -> tuple[Thunk, ...]:
        """
        Return only thunk entries that resolve into known external
        modules.
        """

        return tuple(
            thunk
            for thunk in candidate.thunks
            if (
                thunk.status
                == ThunkStatus.VALID_EXTERNAL
            )
        )

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    @staticmethod
    def format_candidate_summary(
        candidate: IATCandidate,
    ) -> str:

        return (
            f"{candidate.name}:\n"
            f"  start:            0x{candidate.start_va:X}\n"
            f"  end:              0x{candidate.end_va:X}\n"
            f"  size:             0x{candidate.size:X}\n"
            f"  total thunks:     {candidate.total}\n"
            f"  valid external:   {candidate.valid_external}\n"
            f"  invalid internal: {candidate.invalid_internal}\n"
            f"  unresolved:       {candidate.unresolved}\n"
            f"  null:             {candidate.null_entries}\n"
            f"  valid density:    {candidate.valid_density:.3f}\n"
            f"  invalid density:  {candidate.invalid_density:.3f}"
        )

    @classmethod
    def format_analysis_result(
        cls,
        result: IATAnalysisResult,
    ) -> str:

        sections = []

        for candidate in result.candidates:
            sections.append(
                cls.format_candidate_summary(
                    candidate
                )
            )

        sections.append(
            "Selected: "
            f"{result.selected.name}"
        )

        return "\n\n".join(
            sections
        )

    @staticmethod
    def format_thunks(
        candidate: IATCandidate,
        include_valid: bool = True,
        include_invalid: bool = True,
        include_null: bool = False,
    ) -> str:

        lines = []

        for thunk in candidate.thunks:

            if (
                thunk.status
                == ThunkStatus.VALID_EXTERNAL
                and not include_valid
            ):
                continue

            if (
                thunk.status
                in (
                    ThunkStatus.INVALID_INTERNAL,
                    ThunkStatus.UNRESOLVED,
                )
                and not include_invalid
            ):
                continue

            if (
                thunk.status
                == ThunkStatus.NULL
                and not include_null
            ):
                continue

            module = (
                thunk.target_module
                if thunk.target_module
                else "-"
            )

            lines.append(
                f"slot=0x{thunk.slot_va:016X} "
                f"target=0x{thunk.target_va:016X} "
                f"status={thunk.status.value} "
                f"module={module}"
            )

        return "\n".join(
            lines
        )

    def format_range_context(
        self,
        candidate: IATCandidate,
        before: int = 16,
        after: int = 16,
    ) -> str:

        start = max(
            self.image_start,
            candidate.start_va
            - before * self.pointer_size,
        )

        end = min(
            self.image_end,
            candidate.end_va
            + after * self.pointer_size,
        )

        thunks = self._scan_pointer_range(
            start_va=start,
            end_va=end,
        )

        lines = []

        for thunk in thunks:
            module = thunk.target_module or "-"

            lines.append(
                f"slot=0x{thunk.slot_va:016X} "
                f"rva=0x{thunk.slot_va - self.image_start:05X} "
                f"target=0x{thunk.target_va:016X} "
                f"status={thunk.status.value} "
                f"module={module}"
            )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Memory helpers
    # ------------------------------------------------------------------

    def _read_pointer(
        self,
        address: int,
    ) -> int:

        if self.pointer_size == 8:
            return self.debugger.read_qword(
                address
            )

        #
        # We currently only need PE32+ samples.
        #
        # Leaving this explicit rather than silently truncating a qword.
        #
        raise IATError(
            "32-bit pointer reads are not yet implemented"
        )


    def _scan_pointer_range(
        self,
        start_va: int,
        end_va: int,
        chunk_slots: int = 256,
    ) -> tuple[Thunk, ...]:
        '''
        Get live pointer map
        '''

        if end_va <= start_va:
            raise ValueError(
                "end_va must be greater than start_va"
            )

        start_va = (
            start_va
            - (start_va % self.pointer_size)
        )

        scan_size = (
            end_va
            - start_va
        )

        slot_count = (
            scan_size
            // self.pointer_size
        )

        thunks: list[Thunk] = []

        slot_index = 0

        while slot_index < slot_count:

            current_count = min(
                chunk_slots,
                slot_count - slot_index,
            )

            chunk_start = (
                start_va
                + (
                    slot_index
                    * self.pointer_size
                )
            )

            print(
                f"[debug] IAT scan: "
                f"{slot_index}/{slot_count} slots "
                f"@ 0x{chunk_start:X}"
            )

            values = (
                self.debugger.read_qwords(
                    chunk_start,
                    current_count,
                )
            )

            for index, target_va in enumerate(
                values
            ):

                slot_va = (
                    chunk_start
                    + (
                        index
                        * self.pointer_size
                    )
                )

                status, module_name = (
                    self.classify_target(
                        target_va
                    )
                )

                thunks.append(
                    Thunk(
                        slot_va=slot_va,
                        target_va=target_va,
                        status=status,
                        target_module=module_name,
                    )
                )

            slot_index += current_count

        return tuple(thunks)

    def _discover_strict_ranges(
        self,
        thunks: tuple[Thunk, ...],
        min_valid_thunks: int = 4,
        max_null_gap: int = 2,
    ) -> tuple[IATRange, ...]:

        ranges: list[IATRange] = []

        index = 0

        while index < len(thunks):

            if (
                thunks[index].status
                != ThunkStatus.VALID_EXTERNAL
            ):
                index += 1
                continue

            start_index = index
            end_index = index

            valid_count = 0
            null_run = 0

            while index < len(thunks):

                thunk = thunks[index]

                if (
                    thunk.status
                    == ThunkStatus.VALID_EXTERNAL
                ):
                    valid_count += 1
                    null_run = 0
                    end_index = index
                    index += 1
                    continue

                if (
                    thunk.status
                    == ThunkStatus.NULL
                ):
                    null_run += 1

                    if null_run > max_null_gap:
                        break

                    index += 1
                    continue

                break

            if valid_count >= min_valid_thunks:

                start_va = (
                    thunks[start_index].slot_va
                )

                end_va = (
                    thunks[end_index].slot_va
                    + self.pointer_size
                )

                ranges.append(
                    IATRange(
                        name=(
                            f"strict_{len(ranges)}"
                        ),
                        start_va=start_va,
                        size=(
                            end_va
                            - start_va
                        ),
                    )
                )

            if index == start_index:
                index += 1

        return tuple(ranges)

    def _recover_iat_boundaries(
        self,
        thunks: tuple[Thunk, ...],
        strict_ranges: tuple[IATRange, ...],
        max_tail_slots: int = 32,
    ) -> tuple[IATRange, ...]:
        """
        Expand strict IAT cores into probable complete IAT ranges.

        Boundary rules:
            - Include one immediately preceding NULL slot.
            - Walk forward through invalid/unresolved/NULL entries.
            - Stop at the first run of two consecutive NULL slots.
            - Exclude the terminating NULL run.
        """

        index_by_va = {
            thunk.slot_va: index
            for index, thunk in enumerate(thunks)
        }

        recovered: list[IATRange] = []

        for strict_range in strict_ranges:
            start_index = index_by_va[strict_range.start_va]
            end_index = index_by_va[
                strict_range.end_va - self.pointer_size
            ]

            # Include one leading NULL boundary slot.
            if start_index > 0:
                previous = thunks[start_index - 1]

                if previous.status == ThunkStatus.NULL:
                    start_index -= 1

            cursor = end_index + 1
            tail_limit = min(
                len(thunks),
                cursor + max_tail_slots,
            )

            null_run = 0
            recovered_end_index: int | None = None

            while cursor < tail_limit:
                thunk = thunks[cursor]

                if thunk.status == ThunkStatus.VALID_EXTERNAL:
                    # Another legitimate import extends the core.
                    null_run = 0
                    end_index = cursor
                    cursor += 1
                    continue

                if thunk.status == ThunkStatus.NULL:
                    null_run += 1

                    if null_run == 2:
                        # Exclude both NULLs forming the terminator.
                        recovered_end_index = cursor - 2
                        break

                    cursor += 1
                    continue

                # INVALID_INTERNAL or UNRESOLVED remain part of the
                # probable raw IAT until a terminating NULL run.
                null_run = 0
                cursor += 1

            if recovered_end_index is None:
                continue

            start_va = thunks[start_index].slot_va

            end_va = (
                thunks[recovered_end_index].slot_va
                + self.pointer_size
            )

            recovered.append(
                IATRange(
                    name=f"recovered_{len(recovered)}",
                    start_va=start_va,
                    size=end_va - start_va,
                )
            )

        return tuple(recovered)

    def _expand_strict_boundaries(
        self,
        strict_ranges: tuple[IATRange, ...],
        thunks: tuple[Thunk, ...],
        boundary_slots: int = 16,
    ) -> tuple[IATRange, ...]:

        if boundary_slots < 1:
            raise ValueError(
                "boundary_slots must be at least 1"
            )

        index_by_va = {
            thunk.slot_va: index
            for index, thunk in enumerate(thunks)
        }

        expanded: list[IATRange] = []

        for strict_range in strict_ranges:

            start_index = index_by_va[
                strict_range.start_va
            ]

            end_index = index_by_va[
                strict_range.end_va
                - self.pointer_size
            ]

            expanded_start_index = max(
                0,
                start_index - boundary_slots,
            )

            expanded_end_index = min(
                len(thunks) - 1,
                end_index + boundary_slots,
            )

            expanded_start = (
                thunks[
                    expanded_start_index
                ].slot_va
            )

            expanded_end = (
                thunks[
                    expanded_end_index
                ].slot_va
                + self.pointer_size
            )

            expanded.append(
                IATRange(
                    name=f"boundary_{len(expanded)}",
                    start_va=expanded_start,
                    size=expanded_end - expanded_start,
                )
            )

        return tuple(expanded)

    def _discover_expanded_ranges(
        self,
        thunks: tuple[Thunk, ...],
        strict_ranges: tuple[IATRange, ...],
        max_noise_gap: int = 2,
    ) -> tuple[IATRange, ...]:
        """
        Merge neighboring strict IAT ranges when they are separated
        by only a very small number of invalid/unresolved pointer slots.

        This provides a conservative "advanced" candidate analogous
        to expanding a strict IAT search without hard-coding
        sample-specific addresses.
        """

        if max_noise_gap < 1:
            raise ValueError(
                "max_noise_gap must be at least 1"
            )

        if len(strict_ranges) < 2:
            return ()

        thunk_by_va = {
            thunk.slot_va: thunk
            for thunk in thunks
        }

        expanded: list[IATRange] = []

        current_start = strict_ranges[0].start_va
        current_end = strict_ranges[0].end_va

        merged_any = False

        for next_range in strict_ranges[1:]:

            gap_start = current_end
            gap_end = next_range.start_va

            gap_size = (
                gap_end
                - gap_start
            )

            gap_slots = (
                gap_size
                // self.pointer_size
            )

            can_merge = (
                1
                <= gap_slots
                <= max_noise_gap
            )

            if can_merge:

                gap_thunks: list[Thunk] = []

                address = gap_start

                while address < gap_end:

                    thunk = thunk_by_va.get(
                        address
                    )

                    if thunk is None:
                        can_merge = False
                        break

                    gap_thunks.append(
                        thunk
                    )

                    address += self.pointer_size

                if can_merge:

                    allowed_noise = {
                        ThunkStatus.INVALID_INTERNAL,
                        ThunkStatus.UNRESOLVED,
                    }

                    can_merge = all(
                        thunk.status in allowed_noise
                        for thunk in gap_thunks
                    )

            if can_merge:

                current_end = (
                    next_range.end_va
                )

                merged_any = True

                continue

            if merged_any:

                expanded.append(
                    IATRange(
                        name=(
                            f"expanded_{len(expanded)}"
                        ),
                        start_va=current_start,
                        size=(
                            current_end
                            - current_start
                        ),
                    )
                )

            current_start = (
                next_range.start_va
            )

            current_end = (
                next_range.end_va
            )

            merged_any = False

        if merged_any:

            expanded.append(
                IATRange(
                    name=(
                        f"expanded_{len(expanded)}"
                    ),
                    start_va=current_start,
                    size=(
                        current_end
                        - current_start
                    ),
                )
            )

        return tuple(expanded)


    def discover_candidates(
        self,
    ) -> tuple[IATRange, ...]:

        scanned = self._scan_pointer_range(
            start_va=self.image_start,
            end_va=self.image_end,
        )

        strict_ranges = self._discover_strict_ranges(
            scanned
        )

        if not strict_ranges:
            raise IATError(
                "No candidate IAT ranges discovered"
            )

        recovered_ranges = self._recover_iat_boundaries(
            thunks=scanned,
            strict_ranges=strict_ranges,
        )

        if recovered_ranges:
            return recovered_ranges

        return strict_ranges

    def discover_and_analyze(
        self,
    ) -> IATAnalysisResult:
        """
        Discover candidate IAT ranges, analyze each candidate,
        and select the strongest candidate.
        """

        discovered = (
            self.discover_candidates()
        )

        return self.analyze_candidates(
            (
                (
                    candidate.name,
                    candidate.start_va,
                    candidate.size,
                )
                for candidate in discovered
            )
        )