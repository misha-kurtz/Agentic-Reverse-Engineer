import time

from controller.state import AnalysisState


class DynamicAnalysisWorkflow:
    def __init__(
        self,
        windows_vm,
        inetsim_runner,
        wireshark_runner,
        noriben_runner,
        regshot_runner,
        sysmon_runner,
        inetsim_minio_runner,
        pcap_minio_runner,
        windows_minio_runner,
        noriben_timeout: int = 120,
    ):
        self.windows_vm = windows_vm
        self.inetsim_runner = inetsim_runner
        self.wireshark_runner = wireshark_runner
        self.noriben_runner = noriben_runner
        self.regshot_runner = regshot_runner
        self.sysmon_runner = sysmon_runner

        self.inetsim_minio_runner = inetsim_minio_runner
        self.pcap_minio_runner = pcap_minio_runner
        self.windows_minio_runner = windows_minio_runner

        self.noriben_timeout = noriben_timeout

    def run(
        self,
        state: AnalysisState,
        execution_seconds: int = 60,
    ) -> AnalysisState:

        # Prepare Windows collector output directories
        state.noriben_output_dir = (
            self.noriben_runner.prepare_output_dir(
                sample_id=state.sample_id,
                sample_variant=state.sample_variant,
                sha256=state.sha256,
            )
        )

        state.regshot_output_dir = (
            self.regshot_runner.prepare_output_dir(
                sample_id=state.sample_id,
                sample_variant=state.sample_variant,
                sha256=state.sha256,
            )
        )

        state.sysmon_output_dir = (
            self.sysmon_runner.prepare_output_dir(
                sample_id=state.sample_id,
                sample_variant=state.sample_variant,
                sha256=state.sha256,
            )
        )

        try:
            # Verify Sysmon
            if not self.sysmon_runner.is_installed():
                raise RuntimeError(
                    "Sysmon is not installed"
                )

            state.sysmon_verified = True

            # Start INetSim
            self.inetsim_runner.start(
                dynamic_dir=state.ubuntu_dynamic_dir,
            )

            if not self.inetsim_runner.is_running():
                raise RuntimeError(
                    "INetSim failed to start"
                )

            state.inetsim_running = True

            # Start packet capture
            state.pcap_output_path = (
                self.wireshark_runner.start(
                    dynamic_dir=state.ubuntu_dynamic_dir,
                )
            )

            time.sleep(2)

            if not self.wireshark_runner.is_running(
                state.ubuntu_dynamic_dir
            ):
                raise RuntimeError(
                    "Wireshark/tshark failed to start"
                )

            state.packet_capture_running = True

            # Clear Sysmon
            self.sysmon_runner.clear_log()

            # Regshot snapshot 1
            self.regshot_runner.start(
                output_dir=state.regshot_output_dir,
            )

            self.regshot_runner.take_first_snapshot()
            state.regshot_running = True

            # Start Noriben
            self.noriben_runner.start(
                output_dir=state.noriben_output_dir,
                timeout=self.noriben_timeout,
            )

            time.sleep(3)

            if not self.noriben_runner.is_running():
                raise RuntimeError(
                    "Noriben failed to start"
                )

            state.noriben_running = True

            # Execute malware
            self.windows_vm.run_powershell(
                f'Start-Process -FilePath '
                f'"{state.windows_sample_path}"'
            )

            state.sample_executed = True

            # Observation window
            time.sleep(execution_seconds)

            # Finish Noriben
            self.noriben_runner.wait_for_completion(
                timeout=self.noriben_timeout + 60,
            )

            state.noriben_running = False

            # Regshot snapshot 2 + comparison
            self.regshot_runner.take_second_snapshot()

            state.regshot_output_path = (
                self.regshot_runner.compare(
                    output_dir=state.regshot_output_dir,
                )
            )

            state.regshot_running = False

            # Export Sysmon
            state.sysmon_output_path = (
                self.sysmon_runner.export_log(
                    output_dir=state.sysmon_output_dir,
                )
            )

            # Stop tshark
            self.wireshark_runner.stop(
                dynamic_dir=state.ubuntu_dynamic_dir,
            )

            state.packet_capture_running = False

            # Stop INetSim
            self.inetsim_runner.stop()
            state.inetsim_running = False

            # Collect INetSim artifacts
            state.inetsim_output_dir = (
                self.inetsim_runner.collect_artifacts(
                    dynamic_dir=state.ubuntu_dynamic_dir,
                )
            )

            # Upload PCAP
            self.pcap_minio_runner.upload(
                guest_artifact_path=state.pcap_output_path,
                sample_id=state.sample_id,
                sample_variant=state.sample_variant,
                sha256=state.sha256,
                artifact_name="wireshark/traffic.pcapng",
            )

            state.wireshark_upload_complete = True

            # Upload INetSim
            self.inetsim_minio_runner.upload_directory(
                guest_directory_path=state.inetsim_output_dir,
                sample_id=state.sample_id,
                sample_variant=state.sample_variant,
                sha256=state.sha256,
                directory_name="inetsim",
            )

            state.inetsim_upload_complete = True

            # Upload Noriben
            self.windows_minio_runner.upload_directory(
                guest_directory_path=state.noriben_output_dir,
                sample_id=state.sample_id,
                sample_variant=state.sample_variant,
                sha256=state.sha256,
                directory_name="noriben",
            )

            state.noriben_upload_complete = True

            # Upload Regshot
            self.windows_minio_runner.upload(
                guest_artifact_path=state.regshot_output_path,
                sample_id=state.sample_id,
                sample_variant=state.sample_variant,
                sha256=state.sha256,
                artifact_name=(
                    f"regshot/"
                    f"{state.regshot_output_path.name}"
                ),
            )

            state.regshot_upload_complete = True

            # Upload Sysmon
            self.windows_minio_runner.upload(
                guest_artifact_path=state.sysmon_output_path,
                sample_id=state.sample_id,
                sample_variant=state.sample_variant,
                sha256=state.sha256,
                artifact_name="sysmon/sysmon.evtx",
            )

            state.sysmon_upload_complete = True

        finally:
            self.cleanup(state)

        return state

    def clean_artifacts(
        self,
        sample_id: str,
        sample_variant: str,
        sha256: str,
    ) -> None:

        self.pcap_minio_runner.clean_directory_prefix(
            sample_id=sample_id,
            sample_variant=sample_variant,
            sha256=sha256,
            directory_name="wireshark",
        )

        self.inetsim_minio_runner.clean_directory_prefix(
            sample_id=sample_id,
            sample_variant=sample_variant,
            sha256=sha256,
            directory_name="inetsim",
        )

        for directory_name in (
            "noriben",
            "regshot",
            "sysmon",
        ):
            self.windows_minio_runner.clean_directory_prefix(
                sample_id=sample_id,
                sample_variant=sample_variant,
                sha256=sha256,
                directory_name=directory_name,
            )

    def cleanup(
        self,
        state: AnalysisState,
    ) -> None:

        try:
            if self.noriben_runner.is_running():
                self.noriben_runner.stop()
        except Exception:
            pass

        try:
            if self.regshot_runner.is_running():
                self.regshot_runner.stop()
        except Exception:
            pass

        try:
            if (
                state.ubuntu_dynamic_dir is not None
                and self.wireshark_runner.is_running(
                    state.ubuntu_dynamic_dir
                )
            ):
                self.wireshark_runner.stop(
                    state.ubuntu_dynamic_dir
                )
        except Exception:
            pass

        try:
            if self.inetsim_runner.is_running():
                self.inetsim_runner.stop()
        except Exception:
            pass