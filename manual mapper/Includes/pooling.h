#pragma once
#include <Windows.h>
#include <stdio.h>
#include "structs.h"
#include "custom_functions.h"
HANDLE getHandle(LPCWSTR objectType, HANDLE hProcess);
void ExecuteDirectIO(HANDLE hProcess, HANDLE hIoCompletion, LPVOID shellcode_loader) ;
void ExecuteTimerIO(HANDLE hProcess, HANDLE hWorkerFactory, HANDLE hTimer, PVOID shellcode_loader) ;