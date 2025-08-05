#pragma once
#include <windows.h>

#include <stdio.h>
#include <wchar.h>
#include <stdint.h>
#include <string.h>
#include "structs.h"
#ifdef _WIN64
    #define PPEB_PTR __readgsqword( 0x60 )
#else
    #define PPEB_PTR __readfsdword( 0x30 )
#endif
#define RVA_2_VA(T, B, R)   ( T )( ( PBYTE ) B + R )
#define GET_SYMBOL( x )     ( ULONG_PTR )( GetRIP( ) - ( ( ULONG_PTR ) & GetRIP - ( ULONG_PTR ) x ) )
#define C_PTR( x )          ( ( PVOID ) ( x ) )
#define U_PTR( x )          ( ( UINT_PTR ) ( x ) )
#define MAX_DLL_NAME_LENGTH 256;
#define UP -32
#define DOWN 32

#define ntdll_hash 0x22d3b5ed
#define kernel32_hash 0x6ddb9555
#define kernelbase_hash 0xa721952b


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

void debug_print(const char* format, ...);
void* custom_memcpy(void* dest, const void* src, size_t n) ;
void* custom_secure_zero_memory(void* ptr, size_t size);
BOOL custom_virtualfree(void* base);

DWORD runtime_hash(unsigned char* str);
void customRtlSecureZeroMemory(void* ptr, size_t cnt);
void ConvertPWSTRToUnsignedChar(unsigned char* dest, size_t destSize, const wchar_t* src, size_t srcLength);

LPVOID LdrModulePeb( UINT_PTR hModuleHash );
LPVOID LdrFunction( UINT_PTR hModule, UINT_PTR ProcHash );
DWORD_PTR FindInModule(HMODULE* hModule, PBYTE bMask, PCHAR szMask);
BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask);
BOOL FindRetGadget(LPVOID* retGadgetAddress);










//typedefs
typedef LPVOID (WINAPI * VirtualAlloc_t)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

typedef BOOL (WINAPI *VirtualProtect_t)
(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD flNewProtect,
  PDWORD lpflOldProtect
);