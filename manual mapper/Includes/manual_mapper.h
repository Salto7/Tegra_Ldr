#pragma once
#include <windows.h>
#include "structs.h"
#include "custom_functions.h"
#define ENABLE_DLLMAIN 0
#define ENABLE_PEB_INSERTION 1


PIMAGE_NT_HEADERS GetNtHeaders(BYTE* image);
PIMAGE_SECTION_HEADER GetSectionHeaders(BYTE* image) ;
BOOL ApplyRelocations(BYTE* image, BYTE* new_base) ;
BOOL FixImports(BYTE* image);
void ProtectSections(BYTE* image) ;
void RegisterInPEB(BYTE* base, const wchar_t* full_path);
MANUAL_MODULE LoadDllFromMemory(BYTE* buffer, const wchar_t* fake_path);
FARPROC GetExportByName(BYTE* module_base, const char* export_name) ;
BOOL StompExport(BYTE* module_base, const char* export_name, const unsigned char* shellcode, SIZE_T size);
void UnloadDll(MANUAL_MODULE* mod) ;


//for testing
typedef int (WINAPI *DllCanUnloadNowFn)();
