// Test Executable for VirtualProtect Debugger Integration test.

#include <windows.h>
#include <stdio.h>

int main(void)
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);

    SIZE_T size = info.dwPageSize;
    DWORD old_protection = 0;

    void *memory = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!memory)
    {
        printf("VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }

    printf("Allocated memory: %p\n", memory);
    fflush(stdout);

    BOOL result = VirtualProtect(memory, size, PAGE_READONLY, &old_protection);

    printf("VirtualProtect result: %d\n", result);
    fflush(stdout);

    VirtualFree(memory, 0, MEM_RELEASE);
    return result ? 0 : 1;
}