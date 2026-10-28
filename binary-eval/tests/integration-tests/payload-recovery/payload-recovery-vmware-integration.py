# binary-eval/tests/integration-tests/payload-recovery/payload-recovery-vmware-integration.py

import argparse
import json

from pathlib import Path, PureWindowsPath

from runners.vmware import VMwareRunner
from runners.recovery_dispatch import RecoveryDispatchRunner
from workflows.payload_recovery.payload_recovery import PayloadRecoveryWorkflow


'''
End-to-End Payload Recovery Integration Test

Purpose:
    Validate the integration between the host-side payload recovery workflow,
    recovery dispatch runner, and Windows-side recovery entry point.

Tests:
    1. Package the deterministic payload recovery modules.
    2. Deploy the recovery modules into the Windows analysis VM.
    3. Execute the controller-selected recovery method.
    4. Initialize CDB and execute the existing deterministic recovery workflow.
    5. Reconstruct the protected executable.
    6. Generate recovered.bin and recovery_result.json.
    7. Retrieve and validate the recovery metadata.
    8. Verify that PayloadRecoveryWorkflow returns PayloadRecoveryResult.

Prerequisites:
    - Windows analysis VM is running.
    - VMware Tools is operational.
    - Protected executable already exists inside Windows.
    - Python and CDB are installed inside Windows.
    - Required Python recovery dependencies are installed.
'''


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Payload recovery integration test")


    parser.add_argument("--method", required=True, choices=["AUTOMATED_UNPACKING", "AUTOMATED_DECRYPTION"])
    parser.add_argument("--sample", required=True, type=PureWindowsPath)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--python", required=True, type=PureWindowsPath)
    parser.add_argument("--cdb", required=True, type=PureWindowsPath)

    return parser.parse_args()


def main() -> None:

    args = parse_arguments()

    repository_root = Path(__file__).resolve().parent

    guest_code_dir = PureWindowsPath(r"C:\binary-eval\recovery_code")
    guest_archive_path = PureWindowsPath(r"C:\binary-eval\recovery_code.zip")
    guest_output_dir = args.sample.parent / "recovery"

    host_test_dir = repository_root / "test_artifacts" / "payload_recovery"
    host_archive_path = host_test_dir / "recovery.zip"
    host_result_path = host_test_dir / "recovery_result.json"

    host_test_dir.mkdir(parents=True, exist_ok=True)

    # Remove previous host-side results.
    if host_result_path.exists():
        host_result_path.unlink()

    # Initialize the Windows VM interface.
    windows_vm = VMwareRunner(
        vmx_path=r"D:\Virtual Machines\Windows 11 x64\Windows 11 x64\Windows 11 x64.vmx",
        guest_username=r".\misha.kurtz",
        password_env_var="WINDOWS_GUEST_PASSWORD",
        vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
    )

    print("\n========== PAYLOAD RECOVERY INTEGRATION TEST ==========")
    print(f"[test] Recovery method: {args.method}")
    print(f"[test] Protected executable: {args.sample}")
    print(f"[test] Protected SHA-256: {args.sha256}")
    print(f"[test] Windows VM: {windows_vm.vmx_path}")
    print(f"[test] CDB executable: {args.cdb}")


    # Initialize the recovery dispatch runner.
    recovery_dispatch = RecoveryDispatchRunner(
        windows_vm=windows_vm,
        python_path=args.python,
    )

    # Initialize the host-side recovery workflow.
    workflow = PayloadRecoveryWorkflow(recovery_dispatch)

    # Execute the complete payload recovery integration.
    result = workflow.run(
        recovery_method=args.method,
        protected_sha256=args.sha256,
        guest_sample_path=args.sample,
        repository_root=repository_root,
        host_archive_path=host_archive_path,
        guest_archive_path=guest_archive_path,
        guest_code_dir=guest_code_dir,
        guest_output_dir=guest_output_dir,
        host_result_path=host_result_path,
        cdb_path=args.cdb,
    )

    # Validate the normalized recovery result.
    assert result.recovery_successful, "Payload recovery was unsuccessful"
    assert result.recovery_method == args.method, "Recovery method mismatch"
    assert result.protected_sha256.lower() == args.sha256.lower(), "Protected SHA-256 mismatch"
    assert result.protected_path == args.sample, "Protected executable path mismatch"
    assert result.recovered_sha256, "Recovered SHA-256 is missing"
    assert result.recovered_path.name == "recovered.bin", "Unexpected recovered executable filename"
    assert result.oep_rva > 0, "Invalid recovered OEP RVA"
    assert result.iat_rva >= 0, "Invalid IAT RVA"
    assert result.iat_size >= 0, "Invalid IAT size"
    assert result.iat_valid_thunks >= 0, "Invalid valid-thunk count"
    assert result.iat_invalid_thunks >= 0, "Invalid invalid-thunk count"

    # Verify the host-side recovery metadata.
    assert host_result_path.is_file(), "Recovery result JSON was not retrieved"

    with host_result_path.open("r", encoding="utf-8") as file:
        result_data = json.load(file)

    assert result_data["recovery_successful"], "Recovery JSON reports failure"

    print("\n========== RECOVERY RESULTS ==========")
    print(f"[PASS] Recovery method: {result.recovery_method}")
    print(f"[PASS] Protected SHA-256: {result.protected_sha256}")
    print(f"[PASS] Recovered SHA-256: {result.recovered_sha256}")
    print(f"[PASS] Recovered executable: {result.recovered_path}")
    print(f"[PASS] OEP RVA: 0x{result.oep_rva:X}")
    print(f"[PASS] IAT RVA: 0x{result.iat_rva:X}")
    print(f"[PASS] IAT size: 0x{result.iat_size:X}")
    print(f"[PASS] Valid IAT thunks: {result.iat_valid_thunks}")
    print(f"[PASS] Invalid IAT thunks: {result.iat_invalid_thunks}")
    print(f"[PASS] Recovery metadata: {host_result_path}")

    print("\n[PASS] End-to-end payload recovery integration test completed successfully")


if __name__ == "__main__":
    main()