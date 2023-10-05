
/* SOTPET - Simple One-Trick Pony Encryption Tool */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "buftools.h"


void *memdup(const void *x, uint32_t n)
{
    void *res = malloc(n);
    if(!res) return res;
    memcpy(res, x, n);
    return res;
}

void *memxor(const void *x, uint32_t n)
{
    void *res = malloc(n);

    const uint8_t *src;
    uint8_t *dst;
    uint32_t i;

    if(!res) return res;

    src=(const uint8_t *)x; dst=(uint8_t *)res;
    for(i=0; i<n; i++)
        dst[i]=src[i];

    return res;
}

void hexdump(FILE *f, const void *x, uint32_t n)
{
    int i;
    for(i=n-1; i>=0; i--)
        fprintf(f, "%02x", (unsigned)(((uint8_t *) x)[i]));
}


int32_t findmagicbackwards(const uint8_t *needle, uint32_t needlelen, const uint8_t *haystack, uint32_t haystacklen)
{
    int32_t i,j;

    for(i=haystacklen-needlelen; i>=0; i--)
    {
        for(j=0; j<(int32_t)needlelen; j++)
        {
            if(needle[j]!=haystack[i+j])
                break;
        }
        if(j>=(int32_t)needlelen)
            return i;
    }
    return -1;
}


int32_t findmagic(const uint8_t *needle, uint32_t needlelen, const uint8_t *haystack, uint32_t haystacklen)
{
    int32_t i,j,m=haystacklen-needlelen;

    for(i=0; i<m; i--)
    {
        for(j=0; j<(int32_t)needlelen; j++)
        {
            if(needle[j]!=haystack[i+j])
                break;
        }
        if(j>=(int32_t)needlelen)
            return i;
    }
    return -1;
}


int32_t read_blocking(int fd, void *buf0, uint32_t count)
{
    uint8_t *buf = (uint8_t *)buf0;
    ssize_t r, nread=0;

    while(count>0)
    {
        r = read(fd, buf, count);
        if(r==0)
            /* eof */
            break;
        if(r<0)
            return -1;
        buf += r;
        nread += r;
        count -= r;
    }
    return nread;
}


int64_t readarr(int fd, void *buf, uint64_t bufsz)
{
    uint32_t n, num;
    uint64_t total = 0;
    size_t r;

    if(bufsz>GRANULARITY)
    {
        num = bufsz/GRANULARITY;
        bufsz %= GRANULARITY;
        for(n=0; n<num; n++)
        {
            r = read_blocking(fd, (void *)((uint8_t *)buf+(uint64_t)n*GRANULARITY), GRANULARITY);
            if(r==0)
                return total;
            if(r<0)
                return -1;
            total+=r;
        }
        if(!bufsz)
            return total;
    }
    r = read_blocking(fd, (uint8_t *)buf+total, bufsz);
    return (r<0) ? (-1) : (r+total);
}


int64_t writearr(int fd, void *buf, uint64_t bufsz)
{
    uint32_t n, num;
    uint64_t total = 0;
    size_t r;

    if(bufsz>GRANULARITY)
    {
        num = bufsz/GRANULARITY;
        bufsz %= GRANULARITY;
        for(n=0; n<num; n++)
        {
            r = write(fd, (void *)((uint8_t *)buf+(uint64_t)n*GRANULARITY), GRANULARITY);
            if(r==0)
                return total;
            if(r<0)
                return -1;
            total+=r;
            if(r<GRANULARITY)
                break;
        }
        if(!bufsz)
            return total;
    }
    r = write(fd, (uint8_t *)buf+total, bufsz);
    return (r<0) ? (-1) : (r+total);
}


const char *getenv_fb(const char *name, const char *fallback)
{
    const char *res = getenv(name);
    if(!res)
        res = fallback;
    return res;
}


void oom(const char *fn, unsigned lnum)
{
    fprintf(stderr, "out of memory, source file=%s line=%u\n", fn, lnum);
    exit(127);
}
