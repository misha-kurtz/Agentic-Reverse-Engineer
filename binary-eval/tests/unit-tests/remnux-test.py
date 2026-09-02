# REMnux VM control test
from runners.vmware import VMwareRunner

remnux = VMwareRunner(
    vmx_path=r"D:\Virtual Machines\REMnux Linux\REMnux Linux\REMnux Linux.vmx",
    guest_username="misha.kurtz",
    password_env_var="REMNUX_GUEST_PASSWORD",
    vmrun_path=r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
)

remnux.start()

remnux.run_bash(
    "hostname > /tmp/vmware-test.txt && "
    "whoami >> /tmp/vmware-test.txt && "
    "pwd >> /tmp/vmware-test.txt"
)
print("REMnux execution completed")

remnux.stop()