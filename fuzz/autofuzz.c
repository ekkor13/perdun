/*
 * perdun/fuzz/autofuzz.c
 * all-in-one: enumerate devices -> probe IOCTLs -> fuzz each
 *
 * build:  x86_64-w64-mingw32-gcc -O2 -o autofuzz.exe fuzz/autofuzz.c -lntdll
 * usage:  autofuzz.exe                     — full auto
 *         autofuzz.exe -n 500000           — 500k iterations per device
 *         autofuzz.exe -s 512              — max buffer 512 bytes
 *         autofuzz.exe -d C:\fuzzlogs      — log directory
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <winternl.h>
#include <direct.h>

/* ================================================================
 * NT API definitions
 * ================================================================ */

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#endif
#ifndef STATUS_MORE_ENTRIES
#define STATUS_MORE_ENTRIES ((NTSTATUS)0x00000105)
#endif
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif
#ifndef DIRECTORY_TRAVERSE
#define DIRECTORY_TRAVERSE 0x0002
#endif

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef NTSTATUS (NTAPI *pNtOpenDirectoryObject)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *pNtQueryDirectoryObject)(
    HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
typedef VOID (NTAPI *pRtlInitUnicodeString)(
    PUNICODE_STRING, PCWSTR);

static pNtOpenDirectoryObject   fnNtOpenDir;
static pNtQueryDirectoryObject  fnNtQueryDir;
static pRtlInitUnicodeString    fnRtlInitUS;

static int resolve_ntdll(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;
    fnNtOpenDir  = (pNtOpenDirectoryObject)GetProcAddress(ntdll, "NtOpenDirectoryObject");
    fnNtQueryDir = (pNtQueryDirectoryObject)GetProcAddress(ntdll, "NtQueryDirectoryObject");
    fnRtlInitUS  = (pRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
    return (fnNtOpenDir && fnNtQueryDir && fnRtlInitUS);
}

/* ================================================================
 * IOCTL code helpers
 * ================================================================ */

#define CTL_CODE_BUILD(dt, fn, m, a) \
    ((DWORD)(((dt) << 16) | ((a) << 14) | ((fn) << 2) | (m)))

static const DWORD probe_devtypes[] = {
    0x01, 0x02, 0x05, 0x07, 0x09, 0x0C, 0x0F, 0x12,
    0x18, 0x1B, 0x22, 0x24, 0x27, 0x34, 0x38, 0x56,
    0x8000, 0x8001, 0x8010, 0x8020,
};
#define N_PROBE_DEVTYPES (sizeof(probe_devtypes)/sizeof(probe_devtypes[0]))

/* ================================================================
 * RNG
 * ================================================================ */

static unsigned int rng_state;
static void rng_seed(unsigned int s) { rng_state = s; }
static unsigned int rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}
static unsigned int rng_range(unsigned int lo, unsigned int hi)
{
    if (lo >= hi) return lo;
    return lo + (rng_next() % (hi - lo + 1));
}

/* ================================================================
 * Mutation
 * ================================================================ */

static const BYTE boundary_vals[][8] = {
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
    {0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x00},
    {0xFF,0xFF,0xFF,0x7F,0x00,0x00,0x00,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80},
    {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F},
    {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41},
};
#define N_BOUNDARY (sizeof(boundary_vals)/sizeof(boundary_vals[0]))

static void generate_input(BYTE *buf, DWORD size, DWORD *out_size)
{
    int strat = rng_next() % 6;
    *out_size = size;

    switch (strat) {
    case 0: /* random */
        for (DWORD i = 0; i < size; i += 4) {
            DWORD r = rng_next();
            DWORD c = (size - i) < 4 ? (size - i) : 4;
            memcpy(buf + i, &r, c);
        }
        break;
    case 1: /* bitflip */
        memset(buf, 0, size);
        for (int j = 0; j < (int)rng_range(1,8); j++) {
            if (size > 0)
                buf[rng_range(0, size-1)] ^= (1 << (rng_next() % 8));
        }
        break;
    case 2: /* boundary */
        memset(buf, 0, size);
        if (size >= 4) {
            DWORD off = rng_range(0, size-4) & ~3u;
            DWORD c = (size - off) < 8 ? (size - off) : 8;
            memcpy(buf + off, boundary_vals[rng_next() % N_BOUNDARY], c);
        }
        break;
    case 3: memset(buf, 0, size); break;       /* zeros */
    case 4: memset(buf, 0xFF, size); break;     /* 0xFF */
    case 5: /* truncate */
        memset(buf, 0x41, size);
        *out_size = rng_range(0, size);
        break;
    }
}

/* ================================================================
 * Device helpers
 * ================================================================ */

static HANDLE open_device_w(const wchar_t *ntpath)
{
    wchar_t full[512];
    _snwprintf(full, 512, L"\\\\.\\GLOBALROOT%ls", ntpath);
    HANDLE h = CreateFileW(full, 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    return h;
}

static HANDLE open_device_a(const char *ntpath)
{
    char full[512];
    snprintf(full, sizeof(full), "\\\\.\\GLOBALROOT%s", ntpath);
    HANDLE h = CreateFileA(full, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        h = CreateFileA(full, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    return h;
}

/* ================================================================
 * Phase 1: enumerate accessible devices
 * ================================================================ */

#define MAX_DEVICES 256

typedef struct {
    char path[256];       /* e.g. \Device\Bam */
    wchar_t wpath[256];
} device_entry;

static device_entry g_devices[MAX_DEVICES];
static int g_ndevices = 0;

static void enum_devices(void)
{
    HANDLE hDir = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uPath;

    fnRtlInitUS(&uPath, L"\\Device");
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS st = fnNtOpenDir(&hDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
    if (st != STATUS_SUCCESS) return;

    BYTE buf[0x10000];
    ULONG ctx = 0, retlen = 0;
    BOOLEAN first = TRUE;

    while (1) {
        st = fnNtQueryDir(hDir, buf, sizeof(buf), FALSE, first, &ctx, &retlen);
        first = FALSE;
        if (st != STATUS_SUCCESS && st != STATUS_MORE_ENTRIES) break;

        POBJECT_DIRECTORY_INFORMATION info = (POBJECT_DIRECTORY_INFORMATION)buf;
        while (info->Name.Length != 0) {
            if (info->TypeName.Length >= 6 * sizeof(wchar_t) &&
                _wcsnicmp(info->TypeName.Buffer, L"Device", 6) == 0) {

                wchar_t ntpath[256];
                _snwprintf(ntpath, 256, L"\\Device\\%ls", info->Name.Buffer);

                HANDLE h = open_device_w(ntpath);
                if (h != INVALID_HANDLE_VALUE) {
                    CloseHandle(h);
                    if (g_ndevices < MAX_DEVICES) {
                        wcscpy(g_devices[g_ndevices].wpath, ntpath);
                        snprintf(g_devices[g_ndevices].path, 256, "\\Device\\%ls",
                                 info->Name.Buffer);
                        g_ndevices++;
                    }
                }
            }
            info++;
        }
        if (st != STATUS_MORE_ENTRIES) break;
    }
    CloseHandle(hDir);
}

/* ================================================================
 * Phase 2: probe IOCTLs for a device
 * ================================================================ */

#define MAX_IOCTLS 128

typedef struct {
    DWORD codes[MAX_IOCTLS];
    int count;
} ioctl_list;

static DWORD send_ioctl(HANDLE h, DWORD ioctl)
{
    BYTE in[64] = {0}, out[64] = {0};
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(h, ioctl, in, sizeof(in), out, sizeof(out), &ret, NULL);
    return ok ? 0 : GetLastError();
}

static void probe_ioctls(const char *devpath, ioctl_list *out)
{
    out->count = 0;

    HANDLE h = open_device_a(devpath);
    if (h == INVALID_HANDLE_VALUE) return;

    /* calibrate baseline */
    DWORD e1 = send_ioctl(h, 0xDEADBEEF);
    DWORD e2 = send_ioctl(h, 0xCAFEBABE);
    DWORD e3 = send_ioctl(h, 0x99999999);
    DWORD baseline = (e1 == e2 && e2 == e3) ? e1 : 1;

    BYTE seen[256][4] = {{0}};

    for (int dt_i = 0; dt_i < (int)N_PROBE_DEVTYPES; dt_i++) {
        DWORD devtype = probe_devtypes[dt_i];

        /* skip devtype if it aliases the first one's pattern */
        if (dt_i > 0 && out->count > 0) {
            int match = 1;
            for (int c = 0; c < out->count && c < 4; c++) {
                DWORD test = CTL_CODE_BUILD(devtype,
                    (out->codes[c] >> 2) & 0xFFF,
                    out->codes[c] & 3, 0);
                DWORD err = send_ioctl(h, test);
                if (err == baseline || err == 1 || err == 50) {
                    match = 0; break;
                }
            }
            if (match) continue;
        }

        for (DWORD func = 0; func <= 0xFFF; func++) {
            for (DWORD method = 0; method < 4; method++) {
                if (seen[func & 0xFF][method]) continue;

                DWORD ioctl = CTL_CODE_BUILD(devtype, func, method, 0);
                DWORD err = send_ioctl(h, ioctl);

                if (err == baseline || err == 1 || err == 50 ||
                    err == 998 || err == 31 || err == 87)
                    continue;

                seen[func & 0xFF][method] = 1;
                if (out->count < MAX_IOCTLS)
                    out->codes[out->count++] = ioctl;
            }
        }
    }
    CloseHandle(h);
}

/* ================================================================
 * Phase 3: fuzz one device
 * ================================================================ */

static int fuzz_device(const char *devpath, ioctl_list *ioctls,
                       DWORD rounds, DWORD bufsize, const char *logdir)
{
    HANDLE h = open_device_a(devpath);
    if (h == INVALID_HANDLE_VALUE) return 0;

    /* create log file */
    char logpath[512];
    /* sanitize device name for filename */
    char safename[128];
    const char *p = devpath;
    if (strncmp(p, "\\Device\\", 8) == 0) p += 8;
    strncpy(safename, p, sizeof(safename) - 1);
    safename[sizeof(safename) - 1] = 0;
    for (char *c = safename; *c; c++)
        if (*c == '\\' || *c == '/') *c = '_';

    snprintf(logpath, sizeof(logpath), "%s\\%s.log", logdir, safename);
    FILE *log = fopen(logpath, "w");
    if (!log) { CloseHandle(h); return 0; }

    fprintf(log, "# target: %s\n", devpath);
    fprintf(log, "# ioctls: %d\n", ioctls->count);
    for (int i = 0; i < ioctls->count; i++)
        fprintf(log, "# ioctl[%d]: 0x%08lX\n", i, (unsigned long)ioctls->codes[i]);
    fprintf(log, "# rounds: %lu bufsize: %lu\n",
            (unsigned long)rounds, (unsigned long)bufsize);
    fflush(log);

    BYTE *inbuf  = (BYTE *)malloc(bufsize);
    BYTE *outbuf = (BYTE *)malloc(bufsize);
    if (!inbuf || !outbuf) {
        fclose(log);
        CloseHandle(h);
        return 0;
    }

    int interesting = 0;
    time_t t_start = time(NULL);

    for (DWORD i = 0; i < rounds; i++) {
        DWORD ioctl = ioctls->codes[rng_next() % ioctls->count];
        DWORD send_size = 0;
        memset(inbuf, 0, bufsize);
        generate_input(inbuf, bufsize, &send_size);

        /* log BEFORE send */
        fprintf(log, "[%08lu] ioctl=0x%08lX sz=%lu data=",
                (unsigned long)i, (unsigned long)ioctl,
                (unsigned long)send_size);
        DWORD pn = send_size < 64 ? send_size : 64;
        for (DWORD j = 0; j < pn; j++) fprintf(log, "%02X", inbuf[j]);
        if (send_size > 64) fprintf(log, "...");
        fprintf(log, "\n");
        fflush(log);

        DWORD returned = 0;
        memset(outbuf, 0, bufsize);
        BOOL ok = DeviceIoControl(h, ioctl,
                                  inbuf, send_size,
                                  outbuf, bufsize,
                                  &returned, NULL);
        DWORD err = ok ? 0 : GetLastError();

        fprintf(log, "[%08lu] => err=%lu ret=%lu\n",
                (unsigned long)i, (unsigned long)err,
                (unsigned long)returned);

        if (ok && returned > 0) interesting++;
    }

    time_t elapsed = time(NULL) - t_start;
    double rate = elapsed > 0 ? (double)rounds / elapsed : 0;

    fprintf(log, "# done: %.0f iter/sec, interesting: %d\n", rate, interesting);
    fclose(log);
    free(inbuf);
    free(outbuf);
    CloseHandle(h);

    return interesting;
}

/* ================================================================
 * Phase 4: write status file (watchdog reads this from host)
 * ================================================================ */

static void write_status(const char *logdir, const char *devname,
                         const char *state, int device_idx, int total)
{
    char path[512];
    snprintf(path, sizeof(path), "%s\\status.txt", logdir);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "state=%s\n", state);
    fprintf(f, "device=%s\n", devname);
    fprintf(f, "progress=%d/%d\n", device_idx, total);
    fprintf(f, "time=%lld\n", (long long)time(NULL));
    fclose(f);
}

/* ================================================================
 * Main
 * ================================================================ */

int main(int argc, char *argv[])
{
    DWORD rounds_per_device = 1000000;
    DWORD bufsize = 256;
    const char *logdir = "C:\\perdun_logs";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i+1 < argc)
            rounds_per_device = strtoul(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-s") == 0 && i+1 < argc)
            bufsize = strtoul(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-d") == 0 && i+1 < argc)
            logdir = argv[++i];
    }

    rng_seed((unsigned int)time(NULL) ^ GetCurrentProcessId());

    printf("========================================\n");
    printf("  perdun autofuzz — full auto mode\n");
    printf("========================================\n\n");

    /* setup */
    if (!resolve_ntdll()) {
        fprintf(stderr, "[!] failed to resolve ntdll\n");
        return 1;
    }
    _mkdir(logdir);

    /* Phase 1: enumerate */
    printf("[*] Phase 1: enumerating devices...\n");
    enum_devices();
    printf("[+] found %d accessible devices\n\n", g_ndevices);

    /* Phase 2+3: probe & fuzz each */
    int fuzzed = 0, skipped = 0;

    for (int i = 0; i < g_ndevices; i++) {
        printf("[%d/%d] %s\n", i+1, g_ndevices, g_devices[i].path);

        write_status(logdir, g_devices[i].path, "probing", i+1, g_ndevices);

        /* probe IOCTLs */
        printf("  probing IOCTLs...");
        ioctl_list ioctls;
        probe_ioctls(g_devices[i].path, &ioctls);
        printf(" %d found\n", ioctls.count);

        if (ioctls.count == 0) {
            printf("  skipping (no IOCTLs)\n\n");
            skipped++;
            continue;
        }

        /* show found IOCTLs */
        printf("  IOCTLs:");
        for (int j = 0; j < ioctls.count; j++)
            printf(" 0x%08lX", (unsigned long)ioctls.codes[j]);
        printf("\n");

        /* fuzz */
        write_status(logdir, g_devices[i].path, "fuzzing", i+1, g_ndevices);

        printf("  fuzzing %lu rounds...\n", (unsigned long)rounds_per_device);
        time_t t0 = time(NULL);
        int hits = fuzz_device(g_devices[i].path, &ioctls,
                               rounds_per_device, bufsize, logdir);
        time_t elapsed = time(NULL) - t0;

        printf("  done in %lds, interesting: %d\n\n", (long)elapsed, hits);
        fuzzed++;
    }

    write_status(logdir, "none", "complete", g_ndevices, g_ndevices);

    printf("========================================\n");
    printf("  COMPLETE\n");
    printf("  devices fuzzed: %d, skipped: %d\n", fuzzed, skipped);
    printf("  logs in: %s\n", logdir);
    printf("========================================\n");

    return 0;
}
