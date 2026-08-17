/*
 * perdun/fuzz/dumbfuzz.c
 * dumb IOCTL fuzzer — mutate and blast
 *
 * build:  x86_64-w64-mingw32-gcc -O2 -o dumbfuzz.exe fuzz/dumbfuzz.c
 * usage:  dumbfuzz.exe \Device\Bam 0x00220004 0x00220008
 *         dumbfuzz.exe \Device\Bam 0x00220004 -n 50000 -s 256
 *         dumbfuzz.exe \Device\Bam 0x00220004 -l crash.log
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#define MAX_IOCTLS      64
#define DEFAULT_ROUNDS  100000
#define DEFAULT_BUFSIZE 256
#define LOG_FLUSH_EVERY 1       /* flush log every N iterations */

/* ---- rng ---- */

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

/* ---- mutation strategies ---- */

enum mutation {
    MUT_RANDOM,         /* fully random buffer */
    MUT_BITFLIP,        /* flip 1-8 random bits */
    MUT_BOUNDARY,       /* insert boundary values at random offset */
    MUT_ZERO,           /* all zeros */
    MUT_FF,             /* all 0xFF */
    MUT_TRUNCATE,       /* valid-looking but short buffer */
    MUT_COUNT
};

static const BYTE boundary_vals[][8] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    {0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00},  /* INT_MIN 32 */
    {0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00},  /* INT_MAX 32 */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80},  /* INT_MIN 64 */
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F},  /* INT_MAX 64 */
    {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  /* 1 */
    {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  /* 0xFFFF */
    {0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},  /* 0x10000 */
    {0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  /* 0x1000 page size */
    {0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41},  /* AAAA pattern */
};
#define N_BOUNDARY (sizeof(boundary_vals) / sizeof(boundary_vals[0]))

static void mutate_random(BYTE *buf, DWORD size)
{
    for (DWORD i = 0; i < size; i += 4) {
        DWORD r = rng_next();
        DWORD remaining = size - i;
        DWORD copy = remaining < 4 ? remaining : 4;
        memcpy(buf + i, &r, copy);
    }
}

static void mutate_bitflip(BYTE *buf, DWORD size)
{
    if (size == 0) return;
    int flips = rng_range(1, 8);
    for (int i = 0; i < flips; i++) {
        DWORD offset = rng_range(0, size - 1);
        buf[offset] ^= (1 << (rng_next() % 8));
    }
}

static void mutate_boundary(BYTE *buf, DWORD size)
{
    if (size < 4) return;
    DWORD idx = rng_range(0, N_BOUNDARY - 1);
    DWORD offset = rng_range(0, size - 4);
    /* align to 4 bytes */
    offset &= ~3u;
    DWORD copy = (size - offset) < 8 ? (size - offset) : 8;
    memcpy(buf + offset, boundary_vals[idx], copy);
}

static void generate_input(BYTE *buf, DWORD size, DWORD *out_size)
{
    enum mutation strat = rng_next() % MUT_COUNT;
    *out_size = size;

    switch (strat) {
    case MUT_RANDOM:
        mutate_random(buf, size);
        break;

    case MUT_BITFLIP:
        /* start with zeros, then flip */
        memset(buf, 0, size);
        mutate_bitflip(buf, size);
        break;

    case MUT_BOUNDARY:
        memset(buf, 0, size);
        mutate_boundary(buf, size);
        break;

    case MUT_ZERO:
        memset(buf, 0, size);
        break;

    case MUT_FF:
        memset(buf, 0xFF, size);
        break;

    case MUT_TRUNCATE:
        memset(buf, 0x41, size);
        *out_size = rng_range(0, size);
        break;

    default:
        mutate_random(buf, size);
        break;
    }
}

/* ---- logging ---- */

static FILE *g_log = NULL;

static void log_hex(const BYTE *buf, DWORD size, DWORD max_print)
{
    if (!g_log) return;
    DWORD n = size < max_print ? size : max_print;
    for (DWORD i = 0; i < n; i++)
        fprintf(g_log, "%02X", buf[i]);
    if (size > max_print)
        fprintf(g_log, "...");
}

static void log_iteration(DWORD iter, DWORD ioctl, const BYTE *buf,
                           DWORD send_size, DWORD bufsize)
{
    if (!g_log) return;
    fprintf(g_log, "[%08lu] ioctl=0x%08lX size=%lu/%lu data=",
            (unsigned long)iter,
            (unsigned long)ioctl,
            (unsigned long)send_size,
            (unsigned long)bufsize);
    log_hex(buf, send_size, 64);
    fprintf(g_log, "\n");

    if (iter % LOG_FLUSH_EVERY == 0)
        fflush(g_log);
}

static void log_result(DWORD iter, BOOL ok, DWORD err, DWORD returned)
{
    if (!g_log) return;
    fprintf(g_log, "[%08lu] => ok=%d err=%lu ret=%lu\n",
            (unsigned long)iter, ok,
            (unsigned long)err, (unsigned long)returned);
}

/* ---- open device ---- */

static HANDLE open_device(const char *devpath)
{
    char fullpath[512];
    snprintf(fullpath, sizeof(fullpath), "\\\\.\\GLOBALROOT%s", devpath);

    HANDLE h = CreateFileA(fullpath,
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        h = CreateFileA(fullpath, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    }
    return h;
}

/* ---- main ---- */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s <device_path> <ioctl_code> [ioctl_code...] [options]\n"
        "  -n <count>     number of iterations (default %d)\n"
        "  -s <size>      max buffer size in bytes (default %d)\n"
        "  -l <file>      log file (default: perdun_fuzz.log)\n"
        "  -seed <num>    RNG seed (default: time-based)\n"
        "\n"
        "examples:\n"
        "  %s \\Device\\Bam 0x00220004 0x00220008\n"
        "  %s \\Device\\Bam 0x00220004 -n 50000 -s 512\n",
        argv0, DEFAULT_ROUNDS, DEFAULT_BUFSIZE, argv0, argv0);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *devpath = argv[1];
    DWORD ioctls[MAX_IOCTLS];
    int n_ioctls = 0;
    DWORD rounds = DEFAULT_ROUNDS;
    DWORD bufsize = DEFAULT_BUFSIZE;
    const char *logfile = "perdun_fuzz.log";
    unsigned int seed = (unsigned int)time(NULL) ^ GetCurrentProcessId();

    /* parse args: ioctl codes and options */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            rounds = strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            bufsize = strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            logfile = argv[++i];
        } else if (strcmp(argv[i], "-seed") == 0 && i + 1 < argc) {
            seed = strtoul(argv[++i], NULL, 0);
        } else if (argv[i][0] == '0' && (argv[i][1] == 'x' || argv[i][1] == 'X')) {
            if (n_ioctls < MAX_IOCTLS)
                ioctls[n_ioctls++] = strtoul(argv[i], NULL, 16);
        }
    }

    if (n_ioctls == 0) {
        fprintf(stderr, "[!] no IOCTL codes specified\n");
        return 1;
    }

    rng_seed(seed);

    printf("[*] perdun dumbfuzz\n");
    printf("[*] target: %s\n", devpath);
    printf("[*] IOCTLs: ");
    for (int i = 0; i < n_ioctls; i++)
        printf("0x%08lX ", (unsigned long)ioctls[i]);
    printf("\n");
    printf("[*] rounds: %lu, bufsize: %lu, seed: %u\n",
           (unsigned long)rounds, (unsigned long)bufsize, seed);
    printf("[*] log: %s\n", logfile);

    /* open log first — if we BSOD, the log survives */
    g_log = fopen(logfile, "w");
    if (!g_log) {
        fprintf(stderr, "[!] cannot open log file\n");
        return 1;
    }
    fprintf(g_log, "# perdun dumbfuzz log\n");
    fprintf(g_log, "# target: %s\n", devpath);
    fprintf(g_log, "# seed: %u\n", seed);
    fprintf(g_log, "# bufsize: %lu\n", (unsigned long)bufsize);
    for (int i = 0; i < n_ioctls; i++)
        fprintf(g_log, "# ioctl[%d]: 0x%08lX\n", i, (unsigned long)ioctls[i]);
    fflush(g_log);

    HANDLE hDev = open_device(devpath);
    if (hDev == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] cannot open device (error %lu)\n", GetLastError());
        fclose(g_log);
        return 1;
    }
    printf("[+] device opened\n");
    printf("[*] fuzzing...\n\n");

    BYTE *inbuf  = (BYTE *)malloc(bufsize);
    BYTE *outbuf = (BYTE *)malloc(bufsize);
    if (!inbuf || !outbuf) {
        fprintf(stderr, "[!] malloc failed\n");
        return 1;
    }

    DWORD crashes_interesting = 0;
    DWORD errors_seen = 0;
    time_t t_start = time(NULL);

    for (DWORD i = 0; i < rounds; i++) {
        /* pick random IOCTL from the list */
        DWORD ioctl = ioctls[rng_next() % n_ioctls];

        /* generate mutated input */
        DWORD send_size = 0;
        memset(inbuf, 0, bufsize);
        generate_input(inbuf, bufsize, &send_size);

        /* log BEFORE sending — survives BSOD */
        log_iteration(i, ioctl, inbuf, send_size, bufsize);

        /* fire */
        DWORD returned = 0;
        memset(outbuf, 0, bufsize);
        BOOL ok = DeviceIoControl(hDev, ioctl,
                                  inbuf, send_size,
                                  outbuf, bufsize,
                                  &returned, NULL);
        DWORD err = ok ? 0 : GetLastError();

        log_result(i, ok, err, returned);

        /* track interesting results */
        if (ok && returned > 0) {
            errors_seen++;
            if (errors_seen <= 10) {
                printf("  [!] iter %lu: ioctl 0x%08lX returned %lu bytes (SUCCESS)\n",
                       (unsigned long)i, (unsigned long)ioctl,
                       (unsigned long)returned);
            }
        }

        /* progress every 10000 */
        if (i > 0 && i % 10000 == 0) {
            time_t elapsed = time(NULL) - t_start;
            double rate = elapsed > 0 ? (double)i / elapsed : 0;
            printf("  [%lu/%lu] %.0f iter/sec\n",
                   (unsigned long)i, (unsigned long)rounds, rate);
        }
    }

    time_t elapsed = time(NULL) - t_start;
    double rate = elapsed > 0 ? (double)rounds / elapsed : 0;

    printf("\n[*] done: %lu iterations in %ld sec (%.0f iter/sec)\n",
           (unsigned long)rounds, (long)elapsed, rate);
    printf("[*] interesting responses: %lu\n", (unsigned long)errors_seen);
    printf("[*] log saved: %s\n", logfile);

    fclose(g_log);
    free(inbuf);
    free(outbuf);
    CloseHandle(hDev);
    return 0;
}
