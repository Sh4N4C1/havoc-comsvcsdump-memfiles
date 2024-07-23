void UnhookNtApi(char* NtFunction, LPVOID originalbytes, LPVOID trampoline)
{
	//Resolve NtFunction address
	LPVOID ntfunctionAddr = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), NtFunction);

	//Restore original bytes to NtFunction
	SIZE_T bytesWritten = 0;
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)ntfunctionAddr, originalbytes, 16, &bytesWritten);

	//Check whether we hooked an old NtFunction or a new one based on syscall instruction location
	char syscallbytes[] = {0x0f, 0x05};
	SIZE_T bytelen;
	if(memcmp(originalbytes + 8, syscallbytes, 2) == 0)
		bytelen = 21;
	else
		bytelen = 29;

	//Change memory protections so we can zero out the trampoline
	DWORD dwOldProtect;
	VirtualProtect(trampoline, bytelen, PAGE_READWRITE, &dwOldProtect);

	//zero and free
	memset(trampoline, 0, bytelen);
	VirtualFree(trampoline, 0, MEM_RELEASE);
}

void FreePIC(LPVOID PIC, int PICLen)
{
	//Change memory protections so we can zero out the trampoline
	DWORD dwOldProtect;
	VirtualProtect(PIC, PICLen, PAGE_READWRITE, &dwOldProtect);

	memset(PIC, 0, PICLen);
	VirtualFree(PIC, 0, MEM_RELEASE);
}

void CleanMemFiles()
{
	//First unhook all of our functions and free trampolines
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Unhooking API's and freeing trampolines...\n");
	UnhookNtApi("NtCreateFile", pFileInfo->NtCreateFileorigbytes, pFileInfo->NtCreateFiletrampoline);
	UnhookNtApi("NtWriteFile", pFileInfo->NtWriteFileorigbytes, pFileInfo->NtWriteFiletrampoline);
	UnhookNtApi("NtClose", pFileInfo->NtCloseorigbytes, pFileInfo->NtClosetrampoline);
	UnhookNtApi("NtQueryVolumeInformationFile", pFileInfo->NtQueryVolumeInformationFileorigbytes, pFileInfo->NtQueryVolumeInformationFiletrampoline);
	UnhookNtApi("NtQueryInformationFile", pFileInfo->NtQueryInformationFileorigbytes, pFileInfo->NtQueryInformationFiletrampoline);
	UnhookNtApi("NtSetInformationFile", pFileInfo->NtSetInformationFileorigbytes, pFileInfo->NtSetInformationFiletrampoline);
	UnhookNtApi("NtReadFile", pFileInfo->NtReadFileorigbytes, pFileInfo->NtReadFiletrampoline);
	UnhookNtApi("NtOpenFile", pFileInfo->NtOpenFileorigbytes, pFileInfo->NtOpenFiletrampoline);
	/* UnhookNtApi("NtFlushBuffersFile", pFileInfo->NtFlushBuffersFileorigbytes, pFileInfo->NtFlushBuffersFiletrampoline); */

	//Next we can free the injected PIC
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Freeing PIC functions...\n");
	FreePIC(*pFileInfo->PICNtCreateFile, pFileInfo->PICNtCreateFileLen);
	FreePIC(*pFileInfo->PICNtWriteFile, pFileInfo->PICNtWriteFileLen);
	FreePIC(*pFileInfo->PICNtClose, pFileInfo->PICNtCloseLen);
	FreePIC(*pFileInfo->PICNtQueryVolumeInformationFile, pFileInfo->PICNtQueryVolumeInformationFileLen);
	FreePIC(*pFileInfo->PICNtQueryInformationFile, pFileInfo->PICNtQueryInformationFileLen);
	FreePIC(*pFileInfo->PICNtSetInformationFile, pFileInfo->PICNtSetInformationFileLen);
	FreePIC(*pFileInfo->PICNtReadFile, pFileInfo->PICNtReadFileLen);
	FreePIC(*pFileInfo->PICNtOpenFile, pFileInfo->PICNtOpenFileLen);
	/* FreePIC(*pFileInfo->PICNtFlushBuffersFile, pFileInfo->PICNtFlushBuffersFileLen); */

	//Now free our struct
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Freeing FileInfo struct...\n");
	memset(pFileInfo, 0, sizeof(struct FileInfo));
	free(pFileInfo);
	BeaconRemoveValue(MF_FILE_INFO_KEY);

	BeaconPrintf(CALLBACK_OUTPUT,"[+] MemFiles cleaned from Beacon process!\n");
	
}
