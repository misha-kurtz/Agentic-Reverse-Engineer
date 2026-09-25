# Payload Recovery

### Runtime Unpack UPX-packed Samples

``` bash
Launch packed executable under WinDbg/CDB
        ↓
Run to packed PE entry point
        ↓
Verify first instruction is push rbx
        ↓
Record entry RSP
        ↓
Step push rbx
        ↓
Set hardware read/write breakpoint on [new RSP], size 8
        ↓
Run
        ↓
Break near matching pop rbx
        ↓
Find following direct JMP
        ↓
Resolve JMP destination
        ↓
Verify destination lies inside reconstructed .dst/UPX0
        ↓
Step JMP
        ↓
Record OEP VA/RVA
        ↓
Dump reconstructed PE
        ↓
Repair IAT/imports
        ↓
Return recovered executable
```

### Manual Unpacking Workflow Mapped to WinDbg/CDB

|Your x64dbg operation|WinDbg/CDB primitive|
|---|---|
|Launch packed executable|`cdb.exe packed.exe`|
|Run to packed PE EP|breakpoint at `ImageBase + AddressOfEntryPoint`, then `g`|
|Read RIP/RSP|`r rip rsp`|
|Verify `push rbx`|`u @rip L1`|
|Step instruction|`t`|
|Record new RSP|`r rsp`|
|HW access breakpoint on `[RSP]`|`ba r8 @rsp`|
|Continue|`g`|
|Examine break location|`r rip rsp rbx`; `u @rip-...`|
|Confirm matching `pop rbx`|disassemble surrounding instructions|
|Find subsequent direct JMP|decode following instruction(s)|
|Resolve relative target|debugger disassembly or your Python decoder|
|Verify target inside `.dst`|compare target against PE section VA range|
|Break at JMP|`bp <jmp_va>`|
|Execute JMP|`t`|
|Confirm RIP == target|`r rip`|
|Calculate OEP RVA|`RIP - ImageBase`|
|Dump/rebuild PE|separate recovery component|

