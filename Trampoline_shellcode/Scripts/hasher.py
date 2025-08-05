#!/usr/bin/env python
# encoding: utf-8

dlls = [
    'ntdll.dll',
    'KERNEL32.DLL',
    'kernel32.dll',
    'KERNELBASE.dll',
    'msvcrt.dll',
    'user32.dll',
    'f3ahvoas.dll',  
    'chakra_wrapper.dll'
]

functions = [
    'NtAllocateVirtualMemory',
	'NtProtectVirtualMemory',
	'NtCreateThreadEx',
	'NtCreateThread',
	'NtWaitForSingleObject',
    'Sleep',
    'VirtualAlloc',
    'VirtualAllocEx',
    'wcstombs_s',
    'CreateThread',
    'VirtualProtect',
    'CreateTimerQueue',
    'CreateTimerQueueTimer',
    'FreeLibrary',
    'FreeLibraryAndExitThread',
    'MessageBoxA',
    'DeleteTimerQueue',
    'LoadLibraryA',
    'unload',
    'JsAddRef',
    'NtQueryInformationProcess',
    'NtQueryObject',
    'NtSetIoCompletion',
    'NtQueryInformationWorkerFactory',
    'NtSetTimer2'
    
]

def hash_djb2(s):                                                                                                                                
    hash = 5381
    for x in s:
        hash = (( hash << 5) + hash) + ord(x)
    return hash & 0xFFFFFFFF

def print_hash(s):
    print("string: {}, hash: {}".format(s,hex(hash_djb2(s))))

def main():
    for dll in dlls:
        print_hash(dll)
    print("====================")
    
    for function in functions: 
        print_hash(function)

if __name__ == '__main__':
    main()
