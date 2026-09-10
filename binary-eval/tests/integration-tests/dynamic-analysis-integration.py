'''
End-to-end dynamic analysis integration test
Input: three sample variants (original, packed, encrypted)

Malware download from Debian to Windows VM
Default gateway and packet capture from Ubuntu (Tshark, Inetsim server)
Dynamic tools executed on Windows VM (Noriben/Procmon, RegShot, Sysmon)
Execution of malware from Windows VM
Dynamic tools stopped and artifacts uploaded to Debian S3 bucket



Start Debian
Start Ubuntu
Start Windows
        ↓
wait_for_guest() all three
        ↓
wait_for_minio()
        ↓
generate presigned URL for selected variant
        ↓
download + SHA256 verify on Windows
        ↓
clean Ubuntu runtime artifacts
clean Windows collector output
clean MinIO dynamic prefixes
        ↓
prepare Ubuntu + Windows dynamic workspaces
        ↓
start INetSim
start tshark
clear Sysmon
start Noriben
start Regshot
take Regshot snapshot #1
        ↓
execute actual malware sample
        ↓
60-second observation window
        ↓
Regshot snapshot #2 + compare
wait for Noriben
export Sysmon
        ↓
stop tshark
stop INetSim
collect INetSim artifacts
        ↓
upload:
  wireshark/
  inetsim/
  noriben/
  regshot/
  sysmon/
        ↓
verify MinIO objects
'''