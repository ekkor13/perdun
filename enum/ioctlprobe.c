/*
 * perdun/enum/ioctlprobe.c
 * brute-force valid IOCTL codes for a device
 *
 * build:  x86_64-w64-mingw32-gcc -O2 -o ioctlprobe.exe enum/ioctlprobe.c
 * usage:  ioctlprobe.exe \Device\Bam
 *         ioctlprobe.exe \Device\Bam -t 0x22      — only DeviceType 0x22
 *         ioctlprobe.exe \Device\Bam -r 0x800 0xFFF — Function range
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/*
 * IOCTL code layout (32 bits):
 *   [31:16] DeviceType   (16 bits)
 *   [15:14] Access       (2 bits)  — 0=ANY, 1=READ, 2=WRITE, 3=RW
 *   [13:2]  Function     (12 bits) — 0x000..0xFFF
 *   [1:0]   Method       (2 bits)  — 0=BUFFERED,1=IN_DIRECT,2=OUT_DIRECT,3=NEITHER
 */

#define CTL_CODE_BUILD(devtype, func, method, access) \
    ((DWORD)(((devtype) << 16) | ((access) << 14) | ((func) << 2) | (method)))

/* common device types to try when none specified */
static const DWORD common_devtypes[] = {
    0x01, /* FILE_DEVICE_BEEP */
    0x02, /* FILE_DEVICE_CD_ROM */
    0x05, /* FILE_DEVICE_CONTROLLER */
    0x07, /* FILE_DEVICE_DISK */
    0x09, /* FILE_DEVICE_FILE_SYSTEM */
    0x0C, /* FILE_DEVICE_MULTI_UNC_PROVIDER */
    0x0F, /* FILE_DEVICE_NETWORK */
    0x12, /* FILE_DEVICE_NAMED_PIPE */
    0x18, /* FILE_DEVICE_TRANSPORT */
    0x1B, /* FILE_DEVICE_AFD */
    0x22, /* FILE_DEVICE_UNKNOWN — most common for custom drivers */
    0x24, /* FILE_DEVICE_NETWORK_FILE_SYSTEM */
    0x27, /* FILE_DEVICE_KSEC */
    0x34, /* FILE_DEVICE_CRYPT_PROVIDER */
    0x38, /* FILE_DEVICE_MOUNTMGR */
    0x56, /* FILE_DEVICE_CONSOLE */
    0x8000, /* custom range start */
    0x8001,
    0x8010,
    0x8020,
};

static const char *method_str(DWORD m)
{
    switch (m) {
    case 0: return "BUFFERED";
    case 1: return "IN_DIRECT";
    case 2: return "OUT_DIRECT";
    case 3: return "NEITHER";
    default: return "?";
    }
}

static const char *access_str(DWORD a)
{
    switch (a) {
    case 0: return "ANY";
    case 1: return "READ";
    case 2: return "WRITE";
    case 3: return "RW";
    default: return "?";
    }
}

static HANDLE open_device(const char *devpath)
{
    char fullpath[512];
    snprintf(fullpath, sizeof(fullpath), "\\\\.\\GLOBALROOT%s", devpath);

    HANDLE h = CreateFileA(fullpath,
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL,
                           OPEN_EXISTING,
                           0,
                           NULL);

    if (h == INVALID_HANDLE_VALUE) {
        /* retry with zero access */
        h = CreateFileA(fullpath, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    }
    return h;
}

static DWORD send_ioctl(HANDLE hDev, DWORD ioctl)
{
    BYTE inbuf[64]  = {0};
    BYTE outbuf[64] = {0};
    DWORD returned = 0;

    BOOL ok = DeviceIoControl(hDev, ioctl,
                              inbuf, sizeof(inbuf),
                              outbuf, sizeof(outbuf),
                              &returned, NULL);

    return ok ? 0 : GetLastError();
}

/*
 * calibrate: send garbage IOCTLs that no driver handles,
 * remember the error code as "not handled" baseline.
 */
static DWORD baseline_err = 0;

static void calibrate(HANDLE hDev)
{
    DWORD e1 = send_ioctl(hDev, 0xDEADBEEF);
    DWORD e2 = send_ioctl(hDev, 0xCAFEBABE);
    DWORD e3 = send_ioctl(hDev, 0x99999999);

    if (e1 == e2 && e2 == e3) {
        baseline_err = e1;
    } else {
        baseline_err = ERROR_INVALID_FUNCTION;
    }
    printf("[*] baseline error code: %lu\n", (unsigned long)baseline_err);
}

static int probe_ioctl(HANDLE hDev, DWORD ioctl, DWORD *out_err)
{
    DWORD err = send_ioctl(hDev, ioctl);
    *out_err = err;

    if (err == baseline_err)
        return 0;
    if (err == ERROR_INVALID_FUNCTION ||    /* 1 */
        err == ERROR_NOT_SUPPORTED ||       /* 50 */
        err == 998 ||                       /* ERROR_NOACCESS - buffer probe fail */
        err == ERROR_GEN_FAILURE ||         /* 31 */
        err == ERROR_INVALID_PARAMETER)     /* 87 */
        return 0;

    return 1;
}

static void print_ioctl_hit(DWORD ioctl, DWORD devtype, DWORD func,
                            DWORD method, DWORD access, DWORD err)
{
    printf("  0x%08lX  DevType=0x%04lX  Func=0x%03lX  %-11s  %-6s  err=%lu\n",
           (unsigned long)ioctl,
           (unsigned long)devtype,
           (unsigned long)func,
           method_str(method),
           access_str(access),
           (unsigned long)err);
}

/*
 * fingerprint dedup: record which (func & 0xFF, method) combos the first
 * DeviceType hit. if the next DeviceType matches the same pattern exactly,
 * it means the driver ignores DeviceType — skip it.
 */
#define FP_SLOTS 256   /* func & 0xFF */
static BYTE first_fp[FP_SLOTS][4];  /* [func_low][method] = 1 if hit */
static int  first_fp_count = 0;
static int  fp_recorded = 0;
static DWORD first_devtype = 0;

static void fp_record(DWORD func, DWORD method)
{
    first_fp[func & 0xFF][method] = 1;
    first_fp_count++;
}

static int fp_matches(HANDLE hDev, DWORD devtype, DWORD func_lo, DWORD func_hi)
{
    if (!fp_recorded || first_fp_count == 0)
        return 0;

    /* quick probe: check if this devtype hits the same low funcs */
    int matches = 0, misses = 0;
    for (DWORD func = func_lo; func <= func_hi && func < func_lo + 16; func++) {
        for (DWORD method = 0; method < 4; method++) {
            if (!first_fp[func & 0xFF][method])
                continue;
            DWORD ioctl = CTL_CODE_BUILD(devtype, func, method, 0);
            DWORD err = 0;
            if (probe_ioctl(hDev, ioctl, &err))
                matches++;
            else
                misses++;
        }
    }
    /* if all first-16 probes match, it's an alias */
    return (matches > 0 && misses == 0);
}

static int scan_devtype(HANDLE hDev, DWORD devtype,
                        DWORD func_lo, DWORD func_hi)
{
    int found = 0;
    BYTE seen[FP_SLOTS][4] = {{0}};  /* track (func & 0xFF, method) within this scan */

    for (DWORD func = func_lo; func <= func_hi; func++) {
        for (DWORD method = 0; method < 4; method++) {
            /* skip if we already hit this (func & 0xFF, method) combo */
            if (seen[func & 0xFF][method])
                continue;

            int method_hit = 0;
            for (DWORD access = 0; access < 4; access++) {
                DWORD ioctl = CTL_CODE_BUILD(devtype, func, method, access);
                DWORD err = 0;
                if (probe_ioctl(hDev, ioctl, &err)) {
                    if (!method_hit) {
                        print_ioctl_hit(ioctl, devtype, func, method, access, err);
                        found++;
                        method_hit = 1;
                        seen[func & 0xFF][method] = 1;
                        if (!fp_recorded)
                            fp_record(func, method);
                    }
                }
            }
        }
    }

    if (!fp_recorded && found > 0) {
        fp_recorded = 1;
        first_devtype = devtype;
    }

    return found;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s <device_path> [options]\n"
        "  device_path    NT path, e.g. \\Device\\Bam\n"
        "  -t <type>      scan only this DeviceType (hex)\n"
        "  -r <lo> <hi>   Function range (hex, default 0x000-0xFFF)\n"
        "  -a             scan ALL device types 0x0000-0xFFFF (slow)\n"
        "\n"
        "examples:\n"
        "  %s \\Device\\Bam\n"
        "  %s \\Device\\ahcache -t 0x22\n"
        "  %s \\Device\\Afd -r 0x000 0x0FF\n",
        argv0, argv0, argv0, argv0);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *devpath = argv[1];
    DWORD forced_devtype = 0;
    int force_one_type = 0;
    int scan_all = 0;
    DWORD func_lo = 0x000;
    DWORD func_hi = 0xFFF;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            forced_devtype = strtoul(argv[++i], NULL, 16);
            force_one_type = 1;
        } else if (strcmp(argv[i], "-r") == 0 && i + 2 < argc) {
            func_lo = strtoul(argv[++i], NULL, 16);
            func_hi = strtoul(argv[++i], NULL, 16);
        } else if (strcmp(argv[i], "-a") == 0) {
            scan_all = 1;
        }
    }

    printf("[*] perdun ioctlprobe\n");
    printf("[*] target: %s\n", devpath);

    HANDLE hDev = open_device(devpath);
    if (hDev == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] cannot open device (error %lu)\n", GetLastError());
        return 1;
    }
    printf("[+] device opened\n");

    calibrate(hDev);

    printf("[*] function range: 0x%03lX - 0x%03lX\n",
           (unsigned long)func_lo, (unsigned long)func_hi);
    printf("\n  %-12s  %-15s  %-10s  %-11s  %s\n",
           "IOCTL", "DevType", "Function", "Method", "Access");
    printf("  %-12s  %-15s  %-10s  %-11s  %s\n",
           "----------", "----------", "--------", "-----------", "------");

    int total = 0;

    if (force_one_type) {
        printf("[*] scanning DeviceType 0x%04lX\n", (unsigned long)forced_devtype);
        total = scan_devtype(hDev, forced_devtype, func_lo, func_hi);
    } else if (scan_all) {
        printf("[*] scanning ALL device types 0x0000-0xFFFF (this takes a while)\n");
        for (DWORD dt = 0; dt <= 0xFFFF; dt++) {
            if (fp_recorded && fp_matches(hDev, dt, func_lo, func_hi)) {
                continue;  /* alias of first_devtype */
            }
            int n = scan_devtype(hDev, dt, func_lo, func_hi);
            total += n;
            if (n > 0)
                printf("  --- DeviceType 0x%04lX: %d hits ---\n",
                       (unsigned long)dt, n);
        }
    } else {
        printf("[*] scanning common device types\n");
        int ntypes = sizeof(common_devtypes) / sizeof(common_devtypes[0]);
        for (int i = 0; i < ntypes; i++) {
            if (fp_recorded && fp_matches(hDev, common_devtypes[i], func_lo, func_hi)) {
                continue;  /* alias */
            }
            total += scan_devtype(hDev, common_devtypes[i], func_lo, func_hi);
        }
    }

    printf("\n[*] found %d valid IOCTL codes\n", total);

    CloseHandle(hDev);
    return 0;
}
