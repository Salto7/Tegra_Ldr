#include <windows.h>
#include <Macros.h>
#include <Win32.h>

#define EGG_MARKER 0x6767676767676767
//typedef void (*UnloadDllFunc)(void);

SEC( text, A ) VOID Entry( VOID )
{
   //uint64_t __egg_marker = EGG_MARKER;
	INSTANCE Instance = { };
     Instance.Modules.Kernel32   = LdrModulePeb( kernel32_hash ); 
    Instance.Modules.Ntdll      = LdrModulePeb( ntdll_hash );
	Instance.Modules.User32      = LdrModulePeb( user32_hash );
	Instance.Modules.reflective_dll= LdrModulePeb( chakra_wrapper );
	//Instance.Win32.VirtualAlloc = LdrFunction( Instance.Modules.Kernel32, 0x382c0f97 );	
	
	Instance.Win32.unload= LdrFunction( Instance.Modules.reflective_dll, 0x20ce3bc8 );
	Instance.Win32.unload();
}