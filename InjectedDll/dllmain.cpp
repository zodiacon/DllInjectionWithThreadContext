// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

BOOL WINAPI DllMain(HMODULE hModule, DWORD  reason, PVOID reserved) {
    switch (reason) {
	case DLL_PROCESS_ATTACH:
        // just prove this executes
        OutputDebugString(_T("InjectedDll DllMain executes!\n"));
        break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

