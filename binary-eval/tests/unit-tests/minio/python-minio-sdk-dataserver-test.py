# Test whether Python MinIO SDK is accessible through VMwareRunner
from runners.vmware import VMwareRunner

def main():
    datapool = VMwareRunner(
        vmx_path=r"D:\Virtual Machines\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server\Debian 12.x 64-bit Data Pool Server.vmx",
        guest_username="kurtz",
        password_env_var="DATAPOOL_GUEST_PASSWORD",
        vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
    )

    try:
        datapool.run_bash("python3 -c 'from minio import Minio'")
        print("[PASS] MinIO Python SDK is accessible through VMwareRunner")
    except Exception as e:
        print(f"[FAIL] MinIO Python SDK import failed: {e}")


if __name__ == "__main__":
    main()