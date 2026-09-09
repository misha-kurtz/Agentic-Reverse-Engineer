import time
from runners.vmware import VMwareRunner
from runners.ubuntu import UbuntuRunner
from runners.inetsim import INetSimRunner


ubuntu_vm = VMwareRunner(
    vmx_path=(
        r"D:\Virtual Machines\Ubuntu 64-bit Inetsim-Gateway"
        r"\Ubuntu 64-bit Inetsim-Gateway"
        r"\Ubuntu 64-bit Inetsim-Gateway.vmx"
    ),
    guest_username="kurtz",
    password_env_var="UBUNTU_GUEST_PASSWORD",
    vmrun_path=(
        r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"
    ),
)


ubuntu_was_running = ubuntu_vm.is_running()

inetsim_runner = None


try:

    # ---------------------------------------------------------
    # Start Ubuntu
    # ---------------------------------------------------------

    ubuntu_vm.start()

    ubuntu_vm.wait_for_guest(
        shell="bash"
    )

    print("Ubuntu ready")


    # ---------------------------------------------------------
    # Initialize runners
    # ---------------------------------------------------------

    ubuntu_runner = UbuntuRunner(
        ubuntu_vm
    )

    inetsim_runner = INetSimRunner(
        ubuntu_vm
    )


    # ---------------------------------------------------------
    # Clean previous sample workspace
    # ---------------------------------------------------------

    ubuntu_runner.clean_dynamic_workspace(
        sample_id="B001",
        sample_variant="encrypted",
        sha256="test-sha256",
    )

    print("Previous Ubuntu sample workspace cleared")


    # ---------------------------------------------------------
    # Prepare fresh dynamic workspace
    # ---------------------------------------------------------

    dynamic_dir = ubuntu_runner.prepare_dynamic_workspace(
        sample_id="B001",
        sample_variant="encrypted",
        sha256="test-sha256",
    )

    print(
        f"Dynamic workspace prepared: {dynamic_dir}"
    )


    # ---------------------------------------------------------
    # Clean INetSim runtime artifacts
    # ---------------------------------------------------------

    inetsim_runner.clean_runtime_artifacts()

    print("INetSim runtime artifacts cleared")


    # ---------------------------------------------------------
    # Start INetSim
    # ---------------------------------------------------------

    inetsim_runner.start(
        dynamic_dir
    )

    if not inetsim_runner.is_running():
        raise RuntimeError(
            "INetSim failed to start"
        )

    print("INetSim is running")

    ubuntu_vm.run_bash(
        'wget -q '
        '-O /dev/null '
        '"http://192.168.67.5/sample.html"'
    )

    print("Benign INetSim HTTP activity generated")

    ubuntu_vm.run_bash(
    'wget -q '
    '--post-data="sample_id=B001&test=INETSIM_POST_CAPTURE_12345" '
    '-O /dev/null '
    '"http://192.168.67.5/sample.html"'
    )

    print("Benign INetSim HTTP POST generated")
    time.sleep(2)


    # ---------------------------------------------------------
    # Stop INetSim
    # ---------------------------------------------------------

    inetsim_runner.stop()

    if inetsim_runner.is_running():
        raise RuntimeError(
            "INetSim failed to stop"
        )

    print("INetSim stopped successfully")


    # ---------------------------------------------------------
    # Collect INetSim artifacts
    # ---------------------------------------------------------

    inetsim_output_dir = (
        inetsim_runner.collect_artifacts(
            dynamic_dir
        )
    )

    print(
        f"INetSim artifacts collected: "
        f"{inetsim_output_dir}"
    )


    # ---------------------------------------------------------
    # Verify expected output structure
    # ---------------------------------------------------------

    ubuntu_vm.run_bash(
        f'test -d "{inetsim_output_dir}/logs" && '
        f'test -d "{inetsim_output_dir}/reports" && '
        f'test -d "{inetsim_output_dir}/postdata" && '
        f'test -d "{inetsim_output_dir}/ftp_uploads"'
    )

    print("INetSim artifact directories verified")

    # ---------------------------------------------------------
    # Verify collected log artifacts
    # ---------------------------------------------------------

    ubuntu_vm.run_bash(
        f'test -s "{inetsim_output_dir}/logs/main.log" && '
        f'test -s "{inetsim_output_dir}/logs/service.log"'
    )

    print("INetSim logs verified")


    # ---------------------------------------------------------
    # List collected artifacts
    # ---------------------------------------------------------

    ubuntu_vm.run_bash(
        f'find "{inetsim_output_dir}" '
        f'-maxdepth 3 '
        f'-type f '
        f'-printf "%p\\n"'
    )

    print()
    print("INetSim runner test PASSED")


finally:

    # ---------------------------------------------------------
    # Emergency INetSim cleanup
    # ---------------------------------------------------------

    if inetsim_runner is not None:
        try:
            inetsim_runner.stop()
        except Exception:
            pass


    # ---------------------------------------------------------
    # Restore VM ownership state
    # ---------------------------------------------------------

    if not ubuntu_was_running:

        try:
            ubuntu_vm.stop()

        except RuntimeError:
            pass