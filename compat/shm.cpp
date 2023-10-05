
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <stdexcept>

#include "shm.hpp"


                            SotpetSharedMem::SotpetSharedMem(uint64_t id, size_t sz, bool cr)
{
    int r;

    this->id = id;
    sprintf(this->shmfnbuf, SHM_NAME, id);

    //fprintf(stderr, "SHM: %s cr=%d\n", this->shmfnbuf, cr /* = true */);

    this->shmf = shm_open(this->shmfnbuf, O_RDWR | (cr?(O_CREAT|O_TRUNC):0), 0600);
    if(this->shmf<0)
    {
        perror(this->shmfnbuf);
        throw std::runtime_error("i/o");
    }
    this->buflen = sz;
    if(cr)
    {
        r = ftruncate(this->shmf, this->buflen);
        if(r<0)
        {
            perror(this->shmfnbuf);
            throw std::runtime_error("i/o");
        }
    }
}


                            SotpetSharedMem::SotpetSharedMem(uint64_t id, void *buf, size_t sz)
{
    int r;

    this->id = id;
    sprintf(this->shmfnbuf, SHM_NAME, id);

    //fprintf(stderr, "SHM: %s cr=%d\n", this->shmfnbuf, cr /* = true */);

    this->shmf = shm_open(this->shmfnbuf, O_RDWR | O_CREAT|O_TRUNC, 0600);
    if(this->shmf<0)
    {
        perror(this->shmfnbuf);
        throw std::runtime_error("i/o");
    }
    this->buflen = sz;
    r = ftruncate(this->shmf, this->buflen);
    if(r<0)
    {
        perror(this->shmfnbuf);
        throw std::runtime_error("i/o");
    }
    memcpy(this->getbuf(), buf, sz);
}


                           SotpetSharedMem::~SotpetSharedMem()
{
    int r;

    if(this->buf)
    {
        r=munmap(this->buf, this->buflen);
        if(r<0)
        {
            perror(this->shmfnbuf);
        }
        this->buf=NULL;
    }
    if(this->shmf>=0)
    {
        r=shm_unlink(this->shmfnbuf);
        if(r<0)
        {
            perror(this->shmfnbuf);
        }
        this->shmf=-1;
    }
}


            uint8_t        *SotpetSharedMem::getbuf()
{
    if(!this->buf)
        this->buf = mmap(NULL, this->buflen, PROT_READ|PROT_WRITE, MAP_SHARED, this->shmf, 0);
    return (uint8_t *)this->buf;
}


            uint64_t        SotpetSharedMem::getid()
{
    return this->id;
}
