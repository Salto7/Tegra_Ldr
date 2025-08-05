#include <windows.h>
#include <Macros.h>

LPVOID LdrModulePeb( UINT_PTR hModuleHash );
LPVOID LdrFunction( UINT_PTR hModule, UINT_PTR ProcHash );
DWORD_PTR FindInModule(HMODULE* hModule, PBYTE bMask, PCHAR szMask);
BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask);
BOOL FindRetGadget(LPVOID* retGadgetAddress);