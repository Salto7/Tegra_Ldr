#include "custom_functions.h"
void debug_print(const char* format, ...) {
	
	va_list args;
    va_start(args, format);
	printf( format, args);
/*	
    FILE* file = NULL;
    fopen_s(&file, "mylog.txt", "a");

    if (file == NULL) {
        printf("Error opening file\n");
        return;
    }
    va_list args;
    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);
    fclose(file);
*/
}


#ifndef InsertTailList
#define InsertTailList(ListHead, Entry) \
    do { \
        PLIST_ENTRY _EX_Flink = (ListHead); \
        PLIST_ENTRY _EX_Blink = _EX_Flink->Blink; \
        (Entry)->Flink = _EX_Flink; \
        (Entry)->Blink = _EX_Blink; \
        _EX_Blink->Flink = (Entry); \
        _EX_Flink->Blink = (Entry); \
    } while(0)
#endif

#ifndef RemoveEntryList
#define RemoveEntryList(Entry) do { \
    (Entry)->Blink->Flink = (Entry)->Flink; \
    (Entry)->Flink->Blink = (Entry)->Blink; \
} while(0)
#endif



void* custom_memcpy(void* dest, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}


void* custom_secure_zero_memory(void* ptr, size_t size) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (size--) {
        *p++ = 0;
    }
    return ptr;
}

BOOL custom_virtualfree(void* base) {
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* region = (BYTE*)base;
    if (VirtualQuery(region, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return FALSE;
    }
    if (mbi.AllocationBase != base) {
        base = mbi.AllocationBase;
    }

    
    SIZE_T total = 0;
    while (VirtualQuery(base + total, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if ((BYTE*)mbi.AllocationBase != base) break;

        DWORD oldProt;
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProt);
        custom_secure_zero_memory(mbi.BaseAddress, mbi.RegionSize);
        //VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProt, &oldProt);

        total += mbi.RegionSize;
    }

    return VirtualFree(base, 0, MEM_RELEASE);
}

void ConvertPWSTRToUnsignedChar(unsigned char* dest, size_t destSize, const wchar_t* src, size_t srcLength) {
    if (dest == NULL || src == NULL) {
        return;
    }

    size_t i;
    for (i = 0; i < srcLength && i < destSize - 1; ++i) {
        wchar_t wc = src[i];

        // Simple conversion, truncating wide character to unsigned char
        if (wc < 256) {
            dest[i] = (unsigned char)wc;
        } else {
            // Handle characters outside the ASCII range (or other conversion logic as needed)
            dest[i] = '?';  // Use '?' or any placeholder for non-ASCII characters
        }
    }

    dest[i] = '\0'; // Null-terminate the string
}

DWORD runtime_hash(unsigned char* str)
{
    DWORD hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}




// NOTE: The Module hash needs to be a hash from a wide string instead of an ansi string.
PVOID LdrModulePeb(UINT_PTR hModuleHash)
{
    unsigned char cstr_module_name[256] = { 0 };
    PLDR_DATA_TABLE_ENTRY Module = (PLDR_DATA_TABLE_ENTRY)((PEB_MANUAL*)PPEB_PTR)->Ldr->InMemoryOrderModuleList.Flink;
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

LPVOID LdrFunction(UINT_PTR Module, UINT_PTR FunctionHash)
{
    PIMAGE_NT_HEADERS       NtHeader = NULL;
    PIMAGE_EXPORT_DIRECTORY ExpDirectory = NULL;
    PDWORD                  AddrOfFunctions = NULL;
    PDWORD                  AddrOfNames = NULL;
    PWORD                   AddrOfOrdinals = NULL;
    PVOID                   FunctionAddr = NULL;
    PCHAR                   FunctionName = NULL;
    //ANSI_STRING             AnsiString = { 0 };

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



BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    return TRUE;
}

 DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask))
            return (DWORD_PTR)(dwAddress + i);

    return 0;
}

DWORD_PTR FindInModule(HMODULE* hModule, PBYTE bMask, PCHAR szMask)
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

BOOL FindRetGadget(LPVOID* retGadgetAddress ) {
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