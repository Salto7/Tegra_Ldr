#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Unique identifier based on line number
#define UNIQUE_ID(prefix) _CONCAT(prefix, __LINE__)
#define _CONCAT(a, b) a##b

// Per-string key (you can make this more random)
#define GEN_KEY ((uint8_t)(__LINE__ * 31 % 255 + 1))

// Main macro: transparent call
#define OBF(str) obf_decrypt(UNIQUE_ID(_obf_data_), str, GEN_KEY)

// Wraps the actual obfuscated array + decrypt function
#define obf_decrypt(id, str, key) ({ \
    static const uint8_t id[] = { _OBFUSCATE(str, key) }; \
    obf_decrypt_func(id, sizeof(id), key); \
})

// Obfuscate the string using XOR at macro expansion time
#define _OBFUSCATE(s, k) _OBFUSCATE_BYTES(s, k)
#define _XOR_CHAR(s, k, i) (((i) < sizeof(s)) ? ((s)[i] ^ (k)) : 0)

// Expand this macro to support more characters if needed
#define _OBFUSCATE_BYTES(s, k) \
    _XOR_CHAR(s, k, 0), _XOR_CHAR(s, k, 1), _XOR_CHAR(s, k, 2), _XOR_CHAR(s, k, 3), \
    _XOR_CHAR(s, k, 4), _XOR_CHAR(s, k, 5), _XOR_CHAR(s, k, 6), _XOR_CHAR(s, k, 7), \
    _XOR_CHAR(s, k, 8), _XOR_CHAR(s, k, 9), _XOR_CHAR(s, k,10), _XOR_CHAR(s, k,11), \
    _XOR_CHAR(s, k,12), _XOR_CHAR(s, k,13), _XOR_CHAR(s, k,14), _XOR_CHAR(s, k,15), \
    _XOR_CHAR(s, k,16), _XOR_CHAR(s, k,17), _XOR_CHAR(s, k,18), _XOR_CHAR(s, k,19), \
    _XOR_CHAR(s, k,20), _XOR_CHAR(s, k,21), _XOR_CHAR(s, k,22), _XOR_CHAR(s, k,23), \
    _XOR_CHAR(s, k,24), _XOR_CHAR(s, k,25), _XOR_CHAR(s, k,26), _XOR_CHAR(s, k,27), \
    _XOR_CHAR(s, k,28), _XOR_CHAR(s, k,29), _XOR_CHAR(s, k,30), _XOR_CHAR(s, k,31), \
    _XOR_CHAR(s, k,32), _XOR_CHAR(s, k,33), _XOR_CHAR(s, k,34), _XOR_CHAR(s, k,35), \
    _XOR_CHAR(s, k,36), _XOR_CHAR(s, k,37), _XOR_CHAR(s, k,38), _XOR_CHAR(s, k,39), \
    _XOR_CHAR(s, k,40), _XOR_CHAR(s, k,41), _XOR_CHAR(s, k,42), _XOR_CHAR(s, k,43), \
    _XOR_CHAR(s, k,44), _XOR_CHAR(s, k,45), _XOR_CHAR(s, k,46), _XOR_CHAR(s, k,47), \
    _XOR_CHAR(s, k,48), _XOR_CHAR(s, k,49), _XOR_CHAR(s, k,50), _XOR_CHAR(s, k,51), \
    _XOR_CHAR(s, k,52), _XOR_CHAR(s, k,53), _XOR_CHAR(s, k,54), _XOR_CHAR(s, k,55), \
    _XOR_CHAR(s, k,56), _XOR_CHAR(s, k,57), _XOR_CHAR(s, k,58), _XOR_CHAR(s, k,59), \
    _XOR_CHAR(s, k,60), _XOR_CHAR(s, k,61), _XOR_CHAR(s, k,62), _XOR_CHAR(s, k,63), \
    0

#define _WXOR(ch, k) ((ch) ^ (k))

// Shared decryption logic
static LPCWSTR wobf_decrypt(const uint16_t *enc, size_t len, uint8_t key) {
    static wchar_t buf[256];
    size_t i;
    for (i = 0; i < len && enc[i] != 0 && i < 255; i++)
        buf[i] = enc[i] ^ key;
    buf[i] = L'\0';
    return buf;
}
// === Obfuscated widetrings ===

// "TpWorkerFactory"
#define WOBF_TPWORKERFACTORY \
    wobf_decrypt((const uint16_t[]){ \
        _WXOR(L'T',0x5A), _WXOR(L'p',0x5A), _WXOR(L'W',0x5A), _WXOR(L'o',0x5A), \
        _WXOR(L'r',0x5A), _WXOR(L'k',0x5A), _WXOR(L'e',0x5A), _WXOR(L'r',0x5A), \
        _WXOR(L'F',0x5A), _WXOR(L'a',0x5A), _WXOR(L'c',0x5A), _WXOR(L't',0x5A), \
        _WXOR(L'o',0x5A), _WXOR(L'r',0x5A), _WXOR(L'y',0x5A), 0 }, 15, 0x5A)

// "IRTimer"
#define WOBF_IRTIMER \
    wobf_decrypt((const uint16_t[]){ \
        _WXOR(L'I',0x42), _WXOR(L'R',0x42), _WXOR(L'T',0x42), \
        _WXOR(L'i',0x42), _WXOR(L'm',0x42), _WXOR(L'e',0x42), _WXOR(L'r',0x42), 0 }, 7, 0x42)

// "IoCompletion"
#define WOBF_IOCOMPLETION \
    wobf_decrypt((const uint16_t[]){ \
        _WXOR(L'I',0x3D), _WXOR(L'o',0x3D), _WXOR(L'C',0x3D), _WXOR(L'o',0x3D), \
        _WXOR(L'm',0x3D), _WXOR(L'p',0x3D), _WXOR(L'l',0x3D), _WXOR(L'e',0x3D), \
        _WXOR(L't',0x3D), _WXOR(L'i',0x3D), _WXOR(L'o',0x3D), _WXOR(L'n',0x3D), 0 }, 12, 0x3D)

// "C:\\Windows\\System32\\chakra.dll"
#define WOBF_CHAKRA_DLL \
    wobf_decrypt((const uint16_t[]){ \
        _WXOR(L'C',0x6A), _WXOR(L':',0x6A), _WXOR(L'\\',0x6A), _WXOR(L'W',0x6A), \
        _WXOR(L'i',0x6A), _WXOR(L'n',0x6A), _WXOR(L'd',0x6A), _WXOR(L'o',0x6A), \
        _WXOR(L'w',0x6A), _WXOR(L's',0x6A), _WXOR(L'\\',0x6A), _WXOR(L'S',0x6A), \
        _WXOR(L'y',0x6A), _WXOR(L's',0x6A), _WXOR(L't',0x6A), _WXOR(L'e',0x6A), \
        _WXOR(L'm',0x6A), _WXOR(L'3',0x6A), _WXOR(L'2',0x6A), _WXOR(L'\\',0x6A), \
        _WXOR(L'c',0x6A), _WXOR(L'h',0x6A), _WXOR(L'a',0x6A), _WXOR(L'k',0x6A), \
        _WXOR(L'r',0x6A), _WXOR(L'a',0x6A), _WXOR(L'.',0x6A), _WXOR(L'd',0x6A), \
        _WXOR(L'l',0x6A), _WXOR(L'l',0x6A), 0 }, 30, 0x6A)
		
		
// Runtime decryption function
static char* obf_decrypt_func(const uint8_t* enc, size_t len, uint8_t key) {
    static char buf[256];
    if (len >= sizeof(buf)) return NULL;
    for (size_t i = 0; i < len - 1; ++i)
        buf[i] = enc[i] ^ key;
    buf[len - 1] = '\0';
    return buf;
}