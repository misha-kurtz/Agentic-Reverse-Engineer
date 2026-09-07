
``` console
REMnux VM control                          ✓
Debian VM control                          ✓
MinIO readiness                            ✓
Presigned URL generation                   ✓
REMnux sample download via URL             ✓
REMnux SHA256 verification                 ✓

PE metadata extraction runner              ✓
FLOSS string extraction runner             ✓
Capa capabilities runner                   ✓
Ghidra artifacts export script             ✓
Ghidra runner                              ✓
Static analysis workflow  complete         ✓
Static artifact upload from REMnux         ✓

Packer detection                           ✓
Encryption detection                       ✓
Detection workflow complete                ✓

Windows VM control                         ✓
PowerShell execution                       ✓
Windows sample download via URL            ✓
Windows SHA256 verification                ✓

Ubuntu VM control                          ✓
Ubuntu dynamic workspace cleanup           ✓
Ubuntu dynamic workspace creation          ✓
```

``` console
INetSim runner                             ✗
Wireshark/tshark runner                    ✗
Regshot runner                             ✗
Noriben/Procmon runner                     ✗
Sysmon runner                              ✗
Windows malware execution lifecycle        ✗
Dynamic artifact upload from Windows       ✗
Dynamic artifact upload from Ubuntu        ✗
Dynamic workflow                           ✗

Automated payload unpacking from memory    ✗
Automated payload decryption from memory   ✗
Recovery workflow                          ✗
```

noriben.py

``` python
noriben_runner.start(output_dir, timeout=60)

# execute sample here

noriben_runner.wait_for_completion(timeout=90)
```

regshot.py

``` python
# Control paths
&1st shot
&2nd shot
C&ompare
&Clear
&Quit
Plain &TXT
Output path:Edit

# Execution flow
regshot_runner.start(regshot_output_dir)

regshot_runner.take_first_snapshot()

# Start Noriben
# Execute sample
# Wait for analysis window

regshot_runner.take_second_snapshot()

diff_path = regshot_runner.compare(regshot_output_dir)

regshot_runner.clear()
regshot_runner.stop()
```

``` powershell
Get-Process | Where-Object { $_.ProcessName -like "*Regshot*" }
Unregister-ScheduledTask -TaskName "BinaryEval-Regshot" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "BinaryEval-Regshot-App" -Confirm:$false -ErrorAction SilentlyContinue
```


sysmon.py
Windows baseline integration test
INetSim artifact collection
tshark/PCAP artifact collection
dynamic MinIO upload
full DynamicAnalysisWorkflow