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
├── runners/    #Ex. How can I execute capa, FLOSS, Ghidra, etc?
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
├── workflows/ #Ex. What sequence of ops constitutes UPX recovery
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