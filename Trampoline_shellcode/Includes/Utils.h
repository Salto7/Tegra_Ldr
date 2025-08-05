#include <windows.h>

//UINT_PTR HashString( LPVOID String, UINT_PTR Length );
DWORD runtime_hash(unsigned char* str);
void customRtlSecureZeroMemory(void* ptr, size_t cnt);
void ConvertPWSTRToUnsignedChar(unsigned char* dest, size_t destSize, const wchar_t* src, size_t srcLength);