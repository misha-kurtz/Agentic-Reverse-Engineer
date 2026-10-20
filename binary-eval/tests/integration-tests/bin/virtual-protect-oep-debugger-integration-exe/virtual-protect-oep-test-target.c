// Test Executable Code for VirtualProtect Debugger Integration Test

#include <windows.h>
#include <stdio.h>

__declspec(noinline) void OEPTestTarget(void)
{
    volatile int marker = 0x1234;
    printf("[target] Hardware breakpoint target executed: 0x%X\n", marker);
}

int main(void)
{
    SYSTEM_INFO info;
    DWORD old_protection = 0;

    GetSystemInfo(&info);

    void *memory = VirtualAlloc(NULL, info.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!memory)
    {
        printf("[target] VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[target] Calling VirtualProtect\n");
    fflush(stdout);

    BOOL result = VirtualProtect(memory, info.dwPageSize, PAGE_READONLY, &old_protection);

    if (!result)
    {
        printf("[target] VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(memory, 0, MEM_RELEASE);
        return 1;
    }

    printf("[target] VirtualProtect returned successfully\n");
    fflush(stdout);

    OEPTestTarget();

    VirtualFree(memory, 0, MEM_RELEASE);
    return 0;
}