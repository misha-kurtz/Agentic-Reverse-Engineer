# binary-eval/workflows/dynamic_analysis.py

import time
from pathlib import PureWindowsPath

from controller.state import AnalysisState


class DynamicAnalysisWorkflow:
    def __init__(
        self,
        ubuntu_runner,
        inetsim_runner,
        wireshark_runner,
        windows_dispatch,
        regshot_runner,
        noriben_runner,
        sysmon_runner,
        minio_dynamic_runner,
    ):
        self.ubuntu_runner = ubuntu_runner
        self.inetsim_runner = inetsim_runner
        self.wireshark_runner = wireshark_runner
        self.windows_dispatch = windows_dispatch
        self.regshot_runner = regshot_runner
        self.noriben_runner = noriben_runner
        self.sysmon_runner = sysmon_runner
        self.minio_dynamic_runner = minio_dynamic_runner

    def run(
        self,
        state: AnalysisState,
        presigned_url: str,
        execution_seconds: int = 60,
    ) -> AnalysisState:

        # ----------------------------------------------
        # Prepare Ubuntu workspace
        # ----------------------------------------------

        ubuntu_dynamic_dir = (
            self.ubuntu_runner.prepare_dynamic_workspace(
                sample_id=state.sample_id,
                sample_variant=state.sample_variant,
                sha256=state.sha256,
            )
        )

        state.ubuntu_dynamic_dir = ubuntu_dynamic_dir
        state.inetsim_output_dir = (
            ubuntu_dynamic_dir / "inetsim"
        )

        # ----------------------------------------------
        # Start network services / capture
        # ----------------------------------------------

        self.inetsim_runner.start(
            ubuntu_dynamic_dir
        )

        if not self.inetsim_runner.is_running():
            raise RuntimeError(
                "INetSim failed to start"
            )

        state.inetsim_running = True

        pcap_path = self.wireshark_runner.start(
            ubuntu_dynamic_dir
        )

        if not self.wireshark_runner.is_running(
            ubuntu_dynamic_dir
        ):
            raise RuntimeError(
                "Packet capture failed to start"
            )

        state.packet_capture_running = True
        state.pcap_output_path = pcap_path

        # ----------------------------------------------
        # Prepare Windows workspace
        # ----------------------------------------------

        windows_sample_path = PureWindowsPath(
            rf"C:\binary-eval\work\{state.sample_id}"
            rf"\{state.sample_variant}\{state.sha256}"
            rf"\sample.exe"
        )

        self.windows_dispatch.clean_sample_workspace(
            sample_id=state.sample_id,
            sample_variant=state.sample_variant,
            sha256=state.sha256,
        )

        self.windows_dispatch.download_and_verify(
            presigned_url=presigned_url,
            expected_sha256=state.sha256,
            guest_sample_path=windows_sample_path,
        )

        state.dynamic_sample_downloaded = True
        state.dynamic_sha256_verified = True

        # ----------------------------------------------
        # Verify Sysmon
        # ----------------------------------------------

        self.sysmon_runner.verify_running()
        state.sysmon_verified = True

        sysmon_start = (
            self.sysmon_runner.get_marker_time()
        )

        # ----------------------------------------------
        # Regshot before snapshot
        # ----------------------------------------------

        self.regshot_runner.capture_before(
            state
        )

        # ----------------------------------------------
        # Start Noriben / Procmon
        # ----------------------------------------------

        self.noriben_runner.start(state)

        if not self.noriben_runner.is_running():
            raise RuntimeError(
                "Noriben failed to start"
            )

        state.noriben_running = True

        # ----------------------------------------------
        # Execute malware
        # ----------------------------------------------

        self.windows_dispatch.execute_sample(
            windows_sample_path
        )

        state.sample_executed = True

        time.sleep(execution_seconds)

        # ----------------------------------------------
        # Stop Windows collection
        # ----------------------------------------------

        self.noriben_runner.stop(state)
        state.noriben_running = False

        self.regshot_runner.capture_after(state)
        self.regshot_runner.generate_diff(state)

        sysmon_end = (
            self.sysmon_runner.get_marker_time()
        )

        self.sysmon_runner.export_events(
            state=state,
            start_time=sysmon_start,
            end_time=sysmon_end,
        )

        # ----------------------------------------------
        # Stop Ubuntu collection
        # ----------------------------------------------

        self.wireshark_runner.stop(ubuntu_dynamic_dir)
        state.packet_capture_running = False

        self.inetsim_runner.stop()
        state.inetsim_running = False

        # ----------------------------------------------
        # Collect / upload artifacts
        # ----------------------------------------------

        self.minio_dynamic_runner.upload_windows_artifacts(
            state
        )

        self.minio_dynamic_runner.upload_ubuntu_artifacts(
            state
        )

        state.dynamic_upload_complete = True
        state.dynamic_analysis_complete = True

        return state