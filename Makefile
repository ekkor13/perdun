CC       = x86_64-w64-mingw32-gcc
CFLAGS   = -Wall -Wextra -O2
LDFLAGS  = -lntdll

OUTDIR   = build

all: $(OUTDIR)/devenum.exe $(OUTDIR)/ioctlprobe.exe $(OUTDIR)/dumbfuzz.exe $(OUTDIR)/autofuzz.exe

$(OUTDIR)/devenum.exe: enum/devenum.c common/ntdefs.h | $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ enum/devenum.c $(LDFLAGS)

$(OUTDIR)/ioctlprobe.exe: enum/ioctlprobe.c | $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ enum/ioctlprobe.c

$(OUTDIR)/dumbfuzz.exe: fuzz/dumbfuzz.c | $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ fuzz/dumbfuzz.c

$(OUTDIR)/autofuzz.exe: fuzz/autofuzz.c | $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ fuzz/autofuzz.c $(LDFLAGS)

$(OUTDIR):
	mkdir -p $(OUTDIR)

clean:
	rm -rf $(OUTDIR)

.PHONY: all clean
