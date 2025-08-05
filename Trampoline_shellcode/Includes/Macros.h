#include <windows.h>
#pragma once
#ifdef _WIN64
    #define PPEB_PTR __readgsqword( 0x60 )
#else
    #define PPEB_PTR __readfsdword( 0x30 )
#endif

#define WIN32_FUNC( x )     __typeof__( x ) * x
#define SEC( s, x )         __attribute__( ( section( "." #s "$" #x "" ) ) )
#define RVA_2_VA(T, B, R)   ( T )( ( PBYTE ) B + R )
#define GET_SYMBOL( x )     ( ULONG_PTR )( GetRIP( ) - ( ( ULONG_PTR ) & GetRIP - ( ULONG_PTR ) x ) )
#define C_PTR( x )          ( ( PVOID ) ( x ) )
#define U_PTR( x )          ( ( UINT_PTR ) ( x ) )


#define ntdll_hash 0x22d3b5ed
#define kernel32_hash 0x6ddb9555
#define kernelbase_hash 0xa721952b
#define decoyLib_hash 0xcda3fa1a
#define user32_hash 0x5a6bd3f3
#define chakra_wrapper 0x84a2c839

//typedef int (WINAPI * MessageBoxA_t)(HWND, LPSTR, LPSTR, UINT);
//typedef HMODULE (WINAPI *LoadLibraryA_t)(LPSTR lpFileName);

int MessageBoxA(
   HWND   hWnd,
 LPCSTR lpText,
  LPCSTR lpCaption,
   UINT   uType
);

LPVOID VirtualAlloc(
   LPVOID lpAddress,
   SIZE_T dwSize,
   DWORD  flAllocationType,
   DWORD  flProtect
);
void unload();
typedef struct {
	  struct {
        WIN32_FUNC( MessageBoxA );
        WIN32_FUNC( VirtualAlloc );
        WIN32_FUNC( unload );
    } Win32;
    struct {
        HMODULE Kernel32;
        HMODULE Ntdll;
        HMODULE User32;
        HMODULE reflective_dll;
    } Modules;
} INSTANCE, *PINSTANCE;
