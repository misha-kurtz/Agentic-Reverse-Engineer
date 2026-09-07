import json
import tempfile

from pathlib import Path, PurePosixPath

from controller.state import AnalysisState
from detection.packing import detect_packing
from detection.encryption import detect_encryption


class DetectionWorkflow:
    def __init__(self, remnux_vm):
        self.remnux_vm = remnux_vm

    def _read_json(
        self,
        guest_path: PurePosixPath,
    ) -> dict:

        with tempfile.NamedTemporaryFile(
            mode="w+b",
            suffix=".json",
            delete=False,
        ) as temp_file:
            host_path = Path(temp_file.name)

        try:
            self.remnux_vm.copy_from_guest(
                guest_path=str(guest_path),
                host_path=str(host_path),
            )

            if (
                not host_path.exists()
                or host_path.stat().st_size == 0
            ):
                raise RuntimeError(
                    f"Copied JSON artifact is empty: {guest_path}"
                )

            with host_path.open(
                "r",
                encoding="utf-8",
            ) as f:
                return json.load(f)

        finally:
            host_path.unlink(missing_ok=True)

    def run(
        self,
        state: AnalysisState,
    ) -> AnalysisState:

        if state.pe_metadata_path is None:
            raise RuntimeError(
                "PE metadata path is unavailable"
            )

        if state.capa_output_path is None:
            raise RuntimeError(
                "capa output path is unavailable"
            )

        if state.ghidra_output_dir is None:
            raise RuntimeError(
                "Ghidra output directory is unavailable"
            )

        # --------------------------------------------------
        # Load static analysis artifacts.
        # --------------------------------------------------

        pe_data = self._read_json(
            state.pe_metadata_path
        )

        capa_data = self._read_json(
            state.capa_output_path
        )

        ghidra_metrics = self._read_json(
            state.ghidra_output_dir / "metrics.json"
        )

        # --------------------------------------------------
        # Packing detection.
        # --------------------------------------------------

        packing_assessment = detect_packing(
            pe_data=pe_data,
            capa_data=capa_data,
            ghidra_metrics=ghidra_metrics,
        )

        state.packing_detected = (
            packing_assessment.detected
        )

        state.packing_family = (
            packing_assessment.family
        )

        state.packing_confidence = (
            packing_assessment.confidence
        )

        state.packing_indicators = (
            packing_assessment.indicators
        )

        # --------------------------------------------------
        # Encryption detection.
        # --------------------------------------------------

        encryption_assessment = detect_encryption(
            pe_data=pe_data,
            capa_data=capa_data,
            ghidra_metrics=ghidra_metrics,
        )

        state.encrypted_payload_suspected = (
            encryption_assessment.suspected
        )

        state.encryption_family = (
            encryption_assessment.family
        )

        state.encryption_confidence = (
            encryption_assessment.confidence
        )

        state.encryption_indicators = (
            encryption_assessment.indicators
        )

        return state