import hashlib
import os
from pathlib import Path, PureWindowsPath

from runners.vmware import VMwareRunner
from runners.minio_dispatch import MinioDispatchRunner
from runners.windows_dispatch import WindowsDispatchRunner


SAMPLE_ID = "B001"
SAMPLE_VARIANT = "packed"

GUEST_TEST_PATH = PureWindowsPath(r"C:\binary-eval\test\recovered.bin")
HOST_TEMP_URL_PATH = Path(__file__).resolve().parent / "test_artifacts" / "presigned_put_test.txt"

TEST_CONTENT = "Presigned PUT integration test"
TEST_BYTES = TEST_CONTENT.encode("utf-8")
EXPECTED_SHA256 = hashlib.sha256(TEST_BYTES).hexdigest()


def main():
    datapool_vm = VMwareRunner(
        vmx_path=r"D:\Virtual Machines\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server.vmx",
        guest_username="kurtz",
        password_env_var="DATAPOOL_GUEST_PASSWORD",
        vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
    )

    windows_vm = VMwareRunner(
        vmx_path=r"D:\Virtual Machines\Windows 11 x64\Windows 11 x64\Windows 11 x64.vmx",
        guest_username=r".\misha.kurtz",
        password_env_var="WINDOWS_GUEST_PASSWORD",
        vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
    )

    minio_dispatch = MinioDispatchRunner(datapool_vm)
    windows_dispatch = WindowsDispatchRunner(windows_vm)

    HOST_TEMP_URL_PATH.parent.mkdir(parents=True, exist_ok=True)

    print("=== Recovered Payload Upload Integration Test ===")
    print(f"Expected SHA-256: {EXPECTED_SHA256}")

    print("\n[1/4] Checking MinIO availability...")
    minio_dispatch.wait_for_minio()
    print("[PASS] MinIO is available")

    print("\n[2/4] Creating harmless recovered.bin on Windows...")

    content = TEST_CONTENT.replace("'", "''")
    guest_path = str(GUEST_TEST_PATH)

    command = (
        f'New-Item -ItemType Directory -Force -Path "{GUEST_TEST_PATH.parent}" | Out-Null; '
        f"[System.IO.File]::WriteAllText('{guest_path}', '{content}', "
        f"[System.Text.UTF8Encoding]::new($false))"
    )

    windows_vm.run_powershell(command)
    print("[PASS] Test file created")

    print("\n[3/4] Generating presigned PUT URL on Debian...")

    presigned_url = minio_dispatch.generate_presigned_url_put(
        sample_id=SAMPLE_ID,
        recovered_sha256=EXPECTED_SHA256,
        sample_variant=SAMPLE_VARIANT,
        host_temp_path=HOST_TEMP_URL_PATH,
    )

    print("[PASS] Presigned PUT URL generated")

    print("\n[4/4] Verifying SHA-256 and uploading from Windows...")

    # Positive test: This should succeed and upload the recovered payload to MinIO
    windows_dispatch.verify_and_upload(
            presigned_url=presigned_url,
            expected_sha256=EXPECTED_SHA256,
            guest_recovered_path=GUEST_TEST_PATH,
        )

    '''
    # Negative test: This should fail because the expected SHA-256 does not match the actual file's hash
        windows_dispatch.verify_and_upload(
            presigned_url=presigned_url,
            expected_sha256="0" * 64,
            guest_recovered_path=GUEST_TEST_PATH,
        )
    '''
    
    print("[PASS] Recovered payload uploaded successfully")

    object_key = f"{SAMPLE_ID}/{SAMPLE_VARIANT}/recovered/{EXPECTED_SHA256}/recovered.bin"

    print("\n=== Test Complete ===")
    print(f"Bucket: samples")
    print(f"Object: {object_key}")
    print(f"SHA-256: {EXPECTED_SHA256}")


if __name__ == "__main__":
    main()