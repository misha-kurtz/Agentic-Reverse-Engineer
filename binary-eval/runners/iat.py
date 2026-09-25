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
    Minimal interface required from debugger.py.

    CdbDebugger already exposes read_qword(), so it can satisfy this
    protocol without importing CdbDebugger directly and tightly coupling
    this module to a specific debugger implementation.
    """

    def read_qword(
        self,
        address: int,
    ) -> int:
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
    Analyze candidate Import Address Table ranges.

    The current deterministic strategy is:

        1. Enumerate each pointer-sized slot.
        2. Read the runtime value stored in the slot.
        3. Classify the target.
        4. Score candidate ranges.
        5. Select the candidate with the cleanest thunk set.
        6. Return only externally resolved thunks for reconstruction.

    Candidate discovery itself is intentionally separate for now.
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
    ) -> tuple[int, int, int, int, int]:
        """
        Lower tuple wins.

        Primary criterion:
            Fewest invalid thunk entries.

        Tie-breakers:
            1. Fewer internal targets.
            2. Fewer unresolved targets.
            3. More valid external targets.
            4. Smaller candidate range.
        """

        return (
            candidate.invalid_total,
            candidate.invalid_internal,
            candidate.unresolved,
            -candidate.valid_external,
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
            f"  null:             {candidate.null_entries}"
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