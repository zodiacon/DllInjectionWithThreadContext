// InjectDll.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#ifndef _WIN64
void __declspec(naked) InjectedFunction() {
    __asm {
        pushad
        push        11111111h
        mov         eax, 22222222h
        call        eax
        popad
        push        33333333h
        ret
    }
}

// 32 bit assembled code (from some address):

// F91BF0 60                   pushad
// F91BF1 68 11 11 11 11       push        11111111h
// F91BF6 B8 22 22 22 22       mov         eax, 22222222h
// F91BFB FF D0                call        eax
// F91BFD 61                   popad
// F91BFE 68 33 33 33 33       push        33333333h
// F91C03 C3                   ret

#endif


bool DoInjection(HANDLE hProcess, HANDLE hThread, PCSTR dllPath) {
#ifdef _WIN64
    BYTE code[] = {
        // sub rsp, 28h
        0x48, 0x83, 0xec, 0x28,                           
        // mov [rsp + 18], rax
        0x48, 0x89, 0x44, 0x24, 0x18,                     
        // mov [rsp + 10h], rcx
        0x48, 0x89, 0x4c, 0x24, 0x10,
        // mov rcx, 11111111111111111h
        0x48, 0xb9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,     
        // mov rax, 22222222222222222h
        0x48, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        // call rax
        0xff, 0xd0,
        // mov rcx, [rsp + 10h]
        0x48, 0x8b, 0x4c, 0x24, 0x10,
        // mov rax, [rsp + 18h]
        0x48, 0x8b, 0x44, 0x24, 0x18,
        // add rsp, 28h
        0x48, 0x83, 0xc4, 0x28,
        // mov r11, 333333333333333333h
        0x49, 0xbb, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        // jmp r11
        0x41, 0xff, 0xe3
    };
#else
    BYTE code[] = {
        0x60,
        0x68, 0x11, 0x11, 0x11, 0x11,
        0xb8, 0x22, 0x22, 0x22, 0x22,
        0xff, 0xd0,
        0x61,
        0x68, 0x33, 0x33, 0x33, 0x33,
        0xc3
    };
#endif

    const auto page_size = 1 << 12;

    //
    // allocate buffer in target process to hold DLL path and injected function code
    //
    auto buffer = static_cast<char*>(::VirtualAllocEx(hProcess, nullptr, page_size, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!buffer) 
        return false;

    printf("Buffer in remote process: %p\n", buffer);

    //
    // suspend the target thread and get its context
    //
    if (::SuspendThread(hThread) == -1)
        return false;

    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    if (!::GetThreadContext(hThread, &context))
        return false;

    auto loadLibraryAddress = ::GetProcAddress(::GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

#ifdef _WIN64
    // set dll path
    *reinterpret_cast<PVOID*>(code + 0x10) = static_cast<void*>(buffer + page_size / 2);
    // set LoadLibraryA address
    *reinterpret_cast<PVOID*>(code + 0x1a) = static_cast<void*>(loadLibraryAddress);
    // jump address (back to the original code)
    *reinterpret_cast<unsigned long long*>(code + 0x34) = context.Rip;
#else
    // set dll path
    *reinterpret_cast<PVOID*>(code + 2) = static_cast<void*>(buffer + page_size / 2);    
    // set LoadLibraryA address
    *reinterpret_cast<PVOID*>(code + 7) = static_cast<void*>(loadLibraryAddress);
    // jump address (back to the original code)
    *reinterpret_cast<unsigned*>(code + 0xf) = context.Eip;
#endif

    //
    // copy the injected function into the buffer
    //

    if (!::WriteProcessMemory(hProcess, buffer, code, sizeof(code), nullptr))
        return false;

    //
    // copy the DLL name into the buffer
    //
    if (!::WriteProcessMemory(hProcess, buffer + page_size / 2, dllPath, ::strlen(dllPath) + 1, NULL))
        return false;

    //
    // change thread context and let it go!
    //
#ifdef _WIN64
    context.Rip = reinterpret_cast<unsigned long long>(buffer);
#else
    context.Eip = reinterpret_cast<DWORD>(buffer);
#endif
    if (!::SetThreadContext(hThread, &context))
        return false;

    ::ResumeThread(hThread);

    return true;
}

int Error(const char* message) {
    printf("%s (error=%d)\n", message, ::GetLastError());
    return 1;
}

int GetFirstThreadInProcess(int pid) {
    auto hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    THREADENTRY32 te = { sizeof(te) };
    if (!::Thread32First(hSnapshot, &te)) {
        ::CloseHandle(hSnapshot);
        return 0;
    }

    int tid = 0;
    do {
        if (te.th32OwnerProcessID == pid) {
            tid = te.th32ThreadID;
            break;
        }
    } while (::Thread32Next(hSnapshot, &te));

    ::CloseHandle(hSnapshot);
    return tid;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: InjectDll <pid> [tid] <dllPath>\n");
        return 0;
    }

    auto pid = ::atoi(argv[1]);
    auto tid = 0;
    if (argc == 4)
        tid = ::atoi(argv[2]);

    //
    // open handle to process
    //
    auto hProcess = ::OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProcess)
        return Error("Failed to open process handle");

    if (tid == 0)
        tid = GetFirstThreadInProcess(pid);

    if (tid == 0) {
        printf("Failed to get target thread\n");
        return 1;
    }

    //
    // open handle to thread
    //    
    auto hThread = ::OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, tid);
    if (!hThread)
        return Error("Failed to open thread handle");

    if (!DoInjection(hProcess, hThread, argv[argc - 1]))
        return Error("Failed to inject DLL");

    return 0;
}

