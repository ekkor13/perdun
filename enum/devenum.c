/*
 * perdun/enum/devenum.c
 * enumerate \Device objects, try to open each one, report access
 *
 * build:  x86_64-w64-mingw32-gcc -o devenum.exe enum/devenum.c -lntdll
 * usage:  devenum.exe              — scan \Device
 *         devenum.exe \Driver      — scan arbitrary directory
 */

#include <stdio.h>
#include <string.h>
#include "../common/ntdefs.h"

#define QUERY_BUF_SIZE  0x10000
#define GLOBALROOT_PREFIX L"\\\\.\\GLOBALROOT"

static pNtOpenDirectoryObject   fnNtOpenDirectoryObject;
static pNtQueryDirectoryObject  fnNtQueryDirectoryObject;
static pRtlInitUnicodeString    fnRtlInitUnicodeString;

static int resolve_ntdll(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        fprintf(stderr, "[!] GetModuleHandle(ntdll) failed\n");
        return 0;
    }

    fnNtOpenDirectoryObject = (pNtOpenDirectoryObject)
        GetProcAddress(ntdll, "NtOpenDirectoryObject");
    fnNtQueryDirectoryObject = (pNtQueryDirectoryObject)
        GetProcAddress(ntdll, "NtQueryDirectoryObject");
    fnRtlInitUnicodeString = (pRtlInitUnicodeString)
        GetProcAddress(ntdll, "RtlInitUnicodeString");

    if (!fnNtOpenDirectoryObject || !fnNtQueryDirectoryObject ||
        !fnRtlInitUnicodeString) {
        fprintf(stderr, "[!] failed to resolve ntdll exports\n");
        return 0;
    }
    return 1;
}

static HANDLE open_directory(const wchar_t *path)
{
    HANDLE hDir = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uPath;

    fnRtlInitUnicodeString(&uPath, path);
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS st = fnNtOpenDirectoryObject(&hDir,
                                          DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
                                          &oa);
    if (st != STATUS_SUCCESS) {
        fprintf(stderr, "[!] NtOpenDirectoryObject(%ls) = 0x%08lX\n",
                path, (unsigned long)st);
        return NULL;
    }
    return hDir;
}

/* try CreateFileW, return error code (0 = success) */
static DWORD try_open_device(const wchar_t *devname)
{
    wchar_t fullpath[512];
    _snwprintf(fullpath, 512, L"%ls\\%ls", GLOBALROOT_PREFIX, devname);

    HANDLE h = CreateFileW(fullpath,
                           0,                       /* no specific access */
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL,
                           OPEN_EXISTING,
                           0,
                           NULL);
    if (h == INVALID_HANDLE_VALUE)
        return GetLastError();

    CloseHandle(h);
    return 0;
}

static const char *err_to_tag(DWORD err)
{
    switch (err) {
    case 0:                        return "OPEN";
    case ERROR_ACCESS_DENIED:      return "ACCESS_DENIED";
    case ERROR_SHARING_VIOLATION:  return "SHARING_VIOLATION";
    case ERROR_NOT_FOUND:          return "NOT_FOUND";
    case ERROR_INVALID_FUNCTION:   return "INVALID_FUNCTION";
    default:                       return "OTHER";
    }
}

static void enum_and_probe(HANDLE hDir, const wchar_t *dirpath)
{
    BYTE buf[QUERY_BUF_SIZE];
    ULONG ctx = 0;
    ULONG retlen = 0;
    NTSTATUS st;
    BOOLEAN first = TRUE;

    int total = 0, accessible = 0;

    printf("\n%-50s  %-20s  %s\n", "DEVICE", "STATUS", "ERROR");
    printf("%-50s  %-20s  %s\n",
           "--------------------------------------------------",
           "--------------------",
           "-----");

    while (1) {
        st = fnNtQueryDirectoryObject(hDir, buf, sizeof(buf),
                                      FALSE, first, &ctx, &retlen);
        first = FALSE;

        if (st != STATUS_SUCCESS && st != STATUS_MORE_ENTRIES)
            break;

        POBJECT_DIRECTORY_INFORMATION info = (POBJECT_DIRECTORY_INFORMATION)buf;

        while (info->Name.Length != 0) {
            /* filter: only "Device" type objects */
            if (info->TypeName.Length >= 6 * sizeof(wchar_t) &&
                _wcsnicmp(info->TypeName.Buffer, L"Device", 6) == 0) {

                /* build full NT path */
                wchar_t ntpath[512];
                _snwprintf(ntpath, 512, L"%ls\\%ls", dirpath, info->Name.Buffer);

                DWORD err = try_open_device(ntpath);
                const char *tag = err_to_tag(err);

                printf("%-50ls  %-20s  %lu\n", ntpath, tag, (unsigned long)err);

                total++;
                if (err == 0)
                    accessible++;
            }
            info++;
        }

        if (st != STATUS_MORE_ENTRIES)
            break;
    }

    printf("\n[*] total devices: %d, accessible: %d\n", total, accessible);
}

int main(int argc, char *argv[])
{
    const wchar_t *target_dir = L"\\Device";

    if (argc > 1) {
        static wchar_t warg[256];
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, warg, 256);
        target_dir = warg;
    }

    printf("[*] perdun devenum — device enumerator\n");
    printf("[*] scanning: %ls\n", target_dir);

    if (!resolve_ntdll())
        return 1;

    HANDLE hDir = open_directory(target_dir);
    if (!hDir)
        return 1;

    enum_and_probe(hDir, target_dir);

    CloseHandle(hDir);
    return 0;
}
