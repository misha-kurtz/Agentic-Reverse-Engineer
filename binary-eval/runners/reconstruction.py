# binary-eval/runners/reconstruction.py

'''
Reconstruct the Portable Executable from memory

memory dump
+ original PE metadata
+ image base
+ OEP RVA
+ selected IAT
        ↓
recovered.exe
'''