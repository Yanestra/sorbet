
/* SOTPET - Simple One-Trick Pony Encryption Tool */


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#if !BSD
#include <sys/random.h>
#else
#include "bsdfun.h"
#endif
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/param.h>

#include "buftools.h"
#include "sotpet.h"
#include "whirlpool.h"
#include "sotpet_trailer.h"
#include "sotpet_level2.hpp"
#include "camellia.h"
#include "fifo.hpp"
#include "shm.hpp"
#include "sotpet_private.h"
#include "endianess.h"


uint64_t current_blockid = 0;


static int32_t nblocks(int32_t fillbytes, int32_t blocksize)
{
    return (fillbytes+blocksize-1)/blocksize;
}


/* ATTENTION! This function calls perror() directly and will only return 0 if no error occured. */

/* ifi=-1 ofi=-1 slots=1 */

int            sotpet_f2f_smart(bool encflg, int ifi, int ofi, int slots, uint32_t numblocks, uint32_t blocksize, bool usetrailer, struct trailerset *trailer, void *sotpet)
{
    int32_t bufsize = numblocks*blocksize;
    uint32_t should;
    int i, j, err=0, maxi;
    uint64_t total=0, needed=0;
    struct whirlpool whi;
    int32_t r;
    struct encrypted_trailer etr;
    struct plaintext_trailer pln;
    bool eofflg = 0, shortblk;
    //FIFO *ff = new FIFO(MAX(blocksize*2, 0x1000));
    //FIFO *ff = new FIFO(blocksize*(numblocks+1)*slots);
    FIFO *ff = new FIFO(TRAILERPADDING*2);

    SotpetSharedMem **shm;
    int32_t *fill;             /* [slots]                       -> last block number +1 */

    //assert(blocksize>=PADDINGBLOCKSIZE);
    //assert((blocksize%PADDINGBLOCKSIZE)==0);

    // !encflg && usetrailer
    MEMASSERT(ff)
    ff->registermagic_add(sotpet_magic_enc, MAGICSIZE, 0);
    ff->registermagic_add(sotpet_magic2_enc, MAGICSIZE2, OFFMAGIC2);
    ff->registermagic_setsize(ENCRYPTED_TRAILERSIZE);

    if(trailer)
        memset(trailer, 0, sizeof(struct trailerset));

    shm = (SotpetSharedMem **)calloc(slots,sizeof(SotpetSharedMem *));    /* sry, I don't know how to re-alloc new'ed memory */
    MEMASSERT(shm)
    fill = (int32_t *)calloc(slots,sizeof(int32_t));
    MEMASSERT(fill)
    for(i=0; i<slots; i++)
    {
        /* all buffers have 1*sizeof(trailer) at the end when encrypting */
        shm[i] = new SotpetSharedMem(++current_blockid, bufsize + ((encflg && usetrailer) ? blocksize : 0), true);
    }
    whirlpool_init(&whi);
    /* INIT PROCEDURE END */

    /* MAIN LOOP */
    for(;;)
    {
        for(i=0; i<slots; i++)
            fill[i]=0;
        maxi=-1;
        if(!eofflg)
            for(i=0; i<slots; i++)
            {
                maxi=i+1;
                r=readarr(ifi, shm[i]->getbuf(), bufsize);
                if(r<0)
                {
                    err=errno;
                    perror("reading");
                    break;
                }
                fill[i]=r;
                assert(fill[i]<=bufsize);
                if(r>0)
                {
                    if(encflg)
                    {
                        whirlpool_add(&whi, (uint8_t *)shm[i]->getbuf(), r*8);
                        total += r;
                    }
                }
                if(!r)  /* eof */
                {
                    maxi--;
                    eofflg=1;
                    break;
                }
                if(r<bufsize)
                {
                    eofflg=1;
                    break;
                }
            }
        if(err)
            break;
        if(maxi<=0 && encflg)    /* when decoding, we actually may have an empty first buffer */
            break;
        if(maxi==0)
        {
            fill[0]=0;
            maxi=1;
        }

        /* END LOOP PREP */

        if(encflg)
        {
            i = maxi-1;
            if(usetrailer && eofflg)
            {
                /* ifi IS AT ITS END, WE'RE ENCRYPTING AND NOW ATTACH A TRAILER WHICH ALSO SHOULD BE ENCRYPTED */
                /* SPACE AT THE OF THE BUFFER IS ALREADY RESERVED, SO NO NEED TO RE-ALLOCATE */

                memcpy(etr.magic, sotpet_magic_enc, MAGICSIZE);
                memcpy(etr.magic2, sotpet_magic2_enc, MAGICSIZE2);
                etr.version = UINT16_COMPAT(OURVERSION);
                etr.trailersize = UINT16_COMPAT(sizeof etr);
                whirlpool_finalize(&whi, etr.hash);
                etr.filesize = UINT64_COMPAT(total);
                etr.ctime =        /* << this should be the creation_time in the BSD sense */
                etr.mtime = 0;     /* we don't fill these at the moment, 0 is LE and BE the same */
                /* TODO: hw compliance */
                /* this ok because of malloc(bufsize+(encflg?TRAILERPADDING:0)) */
                fprintf(stderr, "enc: trailer i=%d @%d\n", i, fill[i]);
                memcpy(shm[i]->getbuf()+fill[i], &etr, sizeof etr);
                fill[i] += sizeof etr;

                /* if necessary, we'll occupy the extra block at the end of the buffer */
            }

            r = fill[i];
            shortblk = (r%blocksize)!=0;

            /* PAD LAST BLOCK WHEN ENCRYPTING */

            if(shortblk && eofflg)
            {
                should = nblocks(r,blocksize)*blocksize;
                fprintf(stderr, "pad %d bytes\n", should-r);
                assert(should<=bufsize+(encflg ? blocksize : 0));
                if(should>0)
                {
                    r = getrandom(shm[i]->getbuf()+fill[i], should-fill[i], 0);
                    if(r<0)
                    {
                        err=errno;
                        perror("padding");
                    }
                    assert(r==(int)(should-fill[i]));  /* actually, we don't know what to do if we don't get enough random bytes from a source that should work eternally */
                    fill[i] = should;
                }
            }
            else
                assert(!shortblk);
        }
        if(err)
            break;

        for(i=0; i<maxi; i++)
        {
            if(encflg)
            {
                assert((fill[i]%CAMELLIA_BLOCK_SIZE)==0);
                assert((fill[i]%blocksize)==0);
            }
            r=sotpet_add_blockset(sotpet, nblocks(fill[i],blocksize), blocksize, shm[i]->getbuf());
        }
        if(maxi>0)
        {
            r=sotpet_process(sotpet);
            sotpet_release(sotpet);
        }

        /* detect trailer */
        r=-1;
        if(!encflg && usetrailer)
        {
            for(i=0; i<maxi; i++)
            {
                uint8_t *p = shm[i]->getbuf();

                for(j=0; j<fill[i]; j++)
                {
                    ff->push(p[j]);      /* TODO: pushing byte-by-byte is uncool */
                    if(ff->registermagic_detect())
                    {
                        r=j;
                        break;
                    }
                }

                if(r>=0)
                {
                    fprintf(stderr, "dec: trailer i=%d @%d\n", i, r);
                    ff->registermagic_wsget((uint8_t *)&etr, ENCRYPTED_TRAILERSIZE);
                    /* ff->mcpy((uint8_t *)&etr, ENCRYPTED_TRAILERSIZE, r); */
                    etr.version = UINT16_COMPAT(etr.version);
                    etr.trailersize = UINT16_COMPAT(etr.trailersize);
                    etr.filesize = UINT64_COMPAT(etr.filesize);
                    etr.ctime = UINT64_COMPAT(etr.ctime);
                    etr.mtime = UINT64_COMPAT(etr.mtime);

                    memcpy(&trailer->enc, &etr, ENCRYPTED_TRAILERSIZE);
                    /* oopsie, that means, we should truncate here */
                    needed = etr.filesize;
                    fprintf(stderr, "original total size=%lu\n", (long unsigned)needed);

                    r -= ENCRYPTED_TRAILERSIZE;
                    if(r<0)
                    {
                        //if(i>0)
                        //    r += fill[i-1];
                        fprintf(stderr, "WARNING: outstream has %d bytes too long\n", -r);
                        /* the buffer before has already been written, nothing we can do */
                        fill[i] = 0;    // pro forma
                        maxi = i;
                    }
                    else
                    {
                        fill[i] = r;
                        maxi = i+1;
                    }
                    eofflg = 1;
                    break;
                }
            }
        }

        for(i=0; i<maxi; i++)
        {
            if(fill[i]>0)
            {
                if(!encflg && needed)
                    if(fill[i] > needed-total)
                    {
                        fprintf(stderr, "shortened by trailer info: %lu -> %lu (%ld)\n", (long unsigned)(fill[i]+total), (long unsigned)needed, (long)(needed-total));
                        fill[i] = needed-total;
                    }
                if(!encflg && fill[i]>0)
                {
                    whirlpool_add(&whi, shm[i]->getbuf(), fill[i]*8);
                }
                r=writearr(ofi, shm[i]->getbuf(), fill[i]);
                if(r<fill[i])
                {
                    err=errno;
                    perror("write");
                }
                if(!encflg)
                {
                    total+=r;
                    if(needed && total>=needed)
                        break;
                }
            }
            if(err)
                break;
        }

        if(err)
            break;
        if(maxi<=0 && !encflg)
            break;
        if(eofflg && encflg)
            break;

        /* END LOOP */
    }

#if DEBUG
    /* DEBUG */
    if(!encflg && usetrailer)
    {
        r=-1;

        struct encrypted_trailer testbox;
        uint8_t *testboxptr = (uint8_t*) &testbox;

        memcpy(testbox.magic, sotpet_magic_enc, MAGICSIZE);
        memcpy(testbox.magic2, sotpet_magic2_enc, MAGICSIZE2);
        for(int testboxn=0; testboxn<ENCRYPTED_TRAILERSIZE; testboxn++)
        {
            ff->push(testboxptr[testboxn]);      /* TODO: pushing byte-by-byte is uncool */
            if(ff->registermagic_detect())
            {
                fprintf(stderr, "dec debug detect n=%d\n", testboxn);
                r=0;
                break;
            }
        }
        if(r<0)
            ff->dump(0x10);
    }
#endif


    if(!encflg && usetrailer)
    {
        whirlpool_finalize(&whi, trailer->hash);
    }

    /* plaintext trailer (trailer #2) */
    if(encflg && usetrailer)
    {
        memcpy(pln.magic, sotpet_magic_plain, MAGICSIZE);
        pln.version = UINT16_COMPAT(OURVERSION);
        pln.trailersize = UINT16_COMPAT(sizeof pln);
        r=write(ofi, &pln, sizeof pln);
        if(r<(int32_t)sizeof pln)
        {
            err=errno;
            perror("write");
        }
    }

    /* EXIT PROCEDURE START */
    for(i=0; i<slots; i++)
    {
        delete shm[i];
    }
    free(shm);
    free(fill);
    delete ff;
    return err;
}



