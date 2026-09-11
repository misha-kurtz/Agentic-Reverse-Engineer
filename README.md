
### Agentic Multimodal RAG Framework for Robust Reverse Engineering of Packed & Encrypted Malware

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
Static artifact upload from REMnux         ✓
Wire static analysis into controller       ✓

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
INetSim runner                             ✓
Wireshark/tshark runner                    ✓
Regshot runner                             ✓
Noriben/Procmon runner                     ✓
Sysmon runner                              ✓
Windows malware execution lifecycle        ✓
Dynamic artifact upload from Windows       ✓
Dynamic artifact upload from Ubuntu        ✓
Wire dynamic workflow into controller      ✗

Automated payload unpacking from memory    ✗
Automated payload decryption from memory   ✗
Recovery workflow                          ✗
```


``` bash
binary-eval/
│
├── controller/  #Ex. Should I invoke the UPX recovery workflow?
│   ├── __init__.py
│   ├── controller.py
│   ├── state.py
│   ├── policy.py
│   └── decisions.py
│
├── runners/    #Ex. How do I execute capa, FLOSS, Ghidra, etc?
│   ├── base.py
│   ├── vmware.py
│   ├── ghidra.py
│   ├── floss.py
│   ├── capa.py
│   ├── pefile_runner.py
│   ├── procmon.py
│   ├── regshot.py
│   ├── sysmon.py
│   ├── wireshark.py
│   └── x64dbg.py
│
├── workflows/ #Ex. What does static analysis consist of?
│   ├── static_analysis.py
│   ├── dynamic_analysis.py
│   ├── upx_recovery.py
│   └── hyperion_recovery.py
│
├── detection/
│   ├── packing.py
│   └── signatures.py
│
├── artifacts/
│   ├── normalize.py
│   ├── metadata.py
│   ├── manifest.py
│   └── schemas.py
│
├── config/
│   ├── config.yaml
│   └── policies.yaml
│
├── scripts/
│   └── ...
│
└── main.py
```

