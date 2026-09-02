

``` console
Host Controller
      │
      │ presigned URL
      ▼
REMnux VM
      │
      ├── downloads + SHA-256 verifies sample
      │
      ├── PEFile  → pe.json
      ├── FLOSS   → floss.json
      ├── capa    → capa.json
      │
      └── Ghidra
           ├── decompiled/
           ├── assembly/
           ├── cfg/
           ├── functions.tsv
           ├── imports.tsv
           └── callgraph.dot
      │
      │ direct S3 upload 
      ▼
MinIO on Debian Datapool VM
static/<sample_id>/<variant>/<sha256>/
```