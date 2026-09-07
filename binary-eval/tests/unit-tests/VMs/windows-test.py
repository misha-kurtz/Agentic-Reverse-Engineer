# Windows VM control test
from runners.vmware import VMwareRunner

windows_vm = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\Windows 11 x64\Windows 11 x64\Windows 11 x64.vmx",
    guest_username=r".\misha.kurtz",
    password_env_var="WINDOWS_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)


windows_vm.start()
windows_vm.wait_for_guest(shell="windows")

windows_vm.run_powershell(
    r'New-Item -ItemType File -Force -Path "C:\Users\misha.kurtz\vmware-test.txt"'
)

print("Windows VM execution completed")

windows_vm.stop()