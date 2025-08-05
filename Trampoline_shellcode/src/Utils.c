#include <Utils.h>
#include <Macros.h>
SEC( text, B )void ConvertPWSTRToUnsignedChar(unsigned char* dest, size_t destSize, const wchar_t* src, size_t srcLength) {
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

SEC( text, B ) DWORD runtime_hash(unsigned char* str)
{
    DWORD hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}
SEC( text, B ) void customRtlSecureZeroMemory(void* ptr, size_t cnt) {
    // Cast the input pointer to a volatile unsigned char pointer
    volatile unsigned char* vptr = (volatile unsigned char*)ptr;

    // Zero out memory byte by byte
    while (cnt--) {
        *vptr++ = 0;
    }
}