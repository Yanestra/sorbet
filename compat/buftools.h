
/* SOTPET - Simple One-Trick Pony Encryption Tool */

#ifndef GRANULARITY
#define GRANULARITY 0x40000
#endif

void *memdup(const void *x, uint32_t n);
void *memxor(const void *x, uint32_t n);

void oom(const char *fn, unsigned lnum);

void hexdump(FILE *f, const void *x, uint32_t n);

int32_t findmagicbackwards(const uint8_t *needle, uint32_t needlelen, const uint8_t *haystack, uint32_t haystacklen);
int32_t findmagic(const uint8_t *needle, uint32_t needlelen, const uint8_t *haystack, uint32_t haystacklen);

int32_t read_blocking(int fd, void *buf0, uint32_t count);

int64_t readarr(int fd, void *buf, uint64_t bufsz);
int64_t writearr(int fd, void *buf, uint64_t bufsz);

const char *getenv_fb(const char *name, const char *fallback);

#define MEMASSERT(ptr)  { if(!(ptr)) {oom(__FILE__,__LINE__);}}

