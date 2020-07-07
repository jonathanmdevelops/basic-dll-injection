// DLLInject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <stdexcept>
#include <string>
#include <windows.h>

#include "atlstr.h"

int _tmain(int argc, TCHAR* argv[])
{

    HANDLE hTargetProcess;
    DWORD dwTargetProcessId;
    TCHAR pszFullDllPath[MAX_PATH];
    LPVOID lpvDllPathAddress;
    LPVOID lpvLoadLibraryAddress;
    HANDLE hThread;

    if (argc != 3)
    {
        std::cout << "Incorrect number of arguments, a Process ID and a DLL file name are required." << std::endl;
        return 1;
    }

    dwTargetProcessId = _ttoi(argv[1]);

    if (dwTargetProcessId == 0)
    {
        std::cerr << argv[1] << " is not a valid Process ID." << std::endl;
        return 1;
    }

    hTargetProcess = OpenProcess(PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ,
        FALSE,
        dwTargetProcessId);

    if (hTargetProcess == NULL)
    {
        std::cerr << "Failed to open process." << std::endl;
        return 1;
    }

    if (GetFullPathName(argv[2], MAX_PATH, pszFullDllPath, NULL) == 0)
    {
        std::cerr << "Failed to get full path of DLL " << argv[2] << "." << std::endl;
        return 1;
    }

    lpvDllPathAddress = VirtualAllocEx(hTargetProcess,
        0, MAX_PATH,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    if (lpvDllPathAddress == NULL)
    {
        std::cerr << "Failed to allocate memory in Target Process." << std::endl;
        return 1;
    }
    if (WriteProcessMemory(hTargetProcess,
        lpvDllPathAddress,
        pszFullDllPath,
        MAX_PATH,
        NULL) == 0)
    {
        std::cerr << "Failed to write memory in Target Process." << std::endl;
        return 1;
    }

    lpvLoadLibraryAddress = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW");

    if (lpvLoadLibraryAddress == NULL)
    {
        std::cerr << "Failed to get process address of LoadLibraryW in kernel32.dll." << std::endl;
        return 1;
    }

    hThread = CreateRemoteThread(hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE) lpvLoadLibraryAddress, lpvDllPathAddress, 0, NULL);
    std::cout << "Injection complete." << std::endl;
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hTargetProcess, lpvDllPathAddress, 0, MEM_RELEASE);
    CloseHandle(hTargetProcess);
    return 0;
}