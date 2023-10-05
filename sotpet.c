
/* SOTPET - Simple One-Trick Pony Encryption Tool */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#include "sotpet.h"
#include "whirlpool.h"
#include "sotpet_trailer.h"
#include "camellia.h"
#include "buftools.h"
#include "octword.hpp"
#include "shm.hpp"
#include "sotpet_private.h"


static void *myprocess(void *data);
static void keyprep(const char *raw, int rawkeysize, KeyTableType *key1, KeyTableType *key2);


void          *sotpet_init(uint16_t cpus, const char *fun, const char *pass, uint16_t keysize, uint32_t blocksize, uint64_t startblocknum, bool decryptflag)
{
    struct sotpet_container *w = (struct sotpet_container *)malloc(sizeof(struct sotpet_container));

    MEMASSERT(w)
    w->fun = strdup(fun);
    MEMASSERT(w->fun)
    w->decryptflag = decryptflag;
    w->cpus = cpus;
    w->slots = cpus*2;
    w->workset = (struct sotpet_workset *)calloc(w->slots, sizeof(struct sotpet_workset));
    MEMASSERT(w->workset)
    w->blocksize = blocksize;
    w->currentblocknum = w->startblocknum = startblocknum;
    w->slot = 0;

    w->nshkey1 = (KeyTableType *)malloc(CAMELLIA_TABLE_BYTE_LEN);
    w->nshkey2 = (KeyTableType *)malloc(CAMELLIA_TABLE_BYTE_LEN);
    MEMASSERT(w->nshkey1 && w->nshkey2)
    memset(w->nshkey1, 0, CAMELLIA_TABLE_BYTE_LEN);
    memset(w->nshkey2, 0, CAMELLIA_TABLE_BYTE_LEN);

    keyprep(pass, keysize, w->nshkey1, w->nshkey2);

    w->shkey1 = new SotpetSharedMem(++current_blockid, (void *)w->nshkey1, CAMELLIA_TABLE_BYTE_LEN);
    w->shkey2 = new SotpetSharedMem(++current_blockid, (void *)w->nshkey2, CAMELLIA_TABLE_BYTE_LEN);

    return w;
}

int            sotpet_add_blockset(void *wk, uint32_t numblocks, uint32_t blocksize, uint8_t *bufferptr)
{
    struct sotpet_container *w = (struct sotpet_container *)wk;
    int oldslots = w->slots, i;

    assert(blocksize==w->blocksize);
    if(w->slot>=w->slots)
    {
        w->slots += w->cpus;
        w->workset = (struct sotpet_workset *)realloc(w->workset, w->slots * sizeof(struct sotpet_workset));
        MEMASSERT(w->workset)
        for(i=oldslots; i<w->slots; i++)
            memset(w->workset+oldslots, 0, (w->slots-oldslots)*sizeof(struct sotpet_workset));
    }
    w->workset[w->slot].numblocks = numblocks;
    w->workset[w->slot].blocksize = w->blocksize;
    w->workset[w->slot].bufferptr = bufferptr;
    w->workset[w->slot].decryptflag = w->decryptflag;
    w->workset[w->slot].startblocknum = w->currentblocknum;
    w->workset[w->slot].key1 = (KeyTableType *)w->shkey1->getbuf();
    w->workset[w->slot].key2 = (KeyTableType *)w->shkey2->getbuf();

    w->currentblocknum+=numblocks;

    w->slot++;
    return 0;
}

int            sotpet_process(void *wk)
{
    struct sotpet_container *w = (struct sotpet_container *)wk;
    /* pthread_attr_t *at = (pthread_attr_t *)calloc(w->slot, sizeof(pthread_attr_t)); */
    pthread_t *t = (pthread_t *)calloc(w->slot, sizeof(pthread_t));;
    int *rv = (int *)calloc(w->slot, sizeof(int));
    int i,  r=0;

    //fprintf(stderr, "process %d slots\n", w->slot);

    /* MEMASSERT(at) */
    MEMASSERT(t)
    MEMASSERT(rv)

    for(i=0; i<w->slot; i++)
    {
        /* r |= pthread_attr_init(&at[i]); */
        /* r |= pthread_create(&t[i], &at[i], myprocess, (void **)&w->workset[i]); */

        //fprintf(stderr, "\tslot=%d n=%d bsz=%d\n", i, w->workset[i].numblocks, w->workset[i].blocksize);

        r |= pthread_create(&t[i], NULL, myprocess, (void *)&w->workset[i]);
    }
    for(i=0; i<w->slot; i++)
    {
        /* r |= pthread_join(t[i], (void **)&rv[i]); */
        r |= pthread_join(t[i], NULL);
        /* r |= pthread_attr_destroy(&at[i]); */
    }
    //fprintf(stderr, "process r=%d\n", r);
    return r;
}

void           sotpet_release(void *wk)
{
    struct sotpet_container *w = (struct sotpet_container *)wk;
    int i;

    for(i=0; i<w->slot; i++)
    {
        memset(&w->workset[i], 0, sizeof(struct sotpet_workset));
    }
    w->slot = 0;
}

int            sotpet_exit(void *wk)
{
    struct sotpet_container *w = (struct sotpet_container *)wk;

    /* sotpet_reset(wk); */
    free((void *)w->fun);
    free((void *)w->workset);
    free((void *)w->nshkey1);
    free((void *)w->nshkey2);
    delete w->shkey1;
    delete w->shkey2;
    free((void *)w);
    return 0;
}


/* ************************************************************************ */
/* ************************************************************************ */
/* ************************************************************************ */


static void *myprocess(void *data)
{
    struct sotpet_workset *ws = (struct sotpet_workset *)data;
    unsigned long i, b;
    OctWord pos, iv, iv2, tmp, ref;
    uint8_t *p, *p0;

    for(b=0; b<ws->numblocks; b++)
    {
        pos.from(b + ws->startblocknum, 0);

        camellia_encrypt( pos.u.buf, ws->key2, iv.u.buf );

        p0 = (uint8_t *)ws->bufferptr + b * ws->blocksize;
        for(i=0; i<ws->blocksize; i+=CAMELLIA_BUFSIZE)
        {
            p = p0 + i;
            if(!ws->decryptflag)
            {
                tmp.from(p);
                ref=tmp;
                tmp.op_xor(iv);
                camellia_encrypt( tmp.u.buf, ws->key1, iv.u.buf );
                assert(!ref.equals(iv));
                iv.to(p);

                OctWord probe;
                probe.from(p);
                assert(probe.equals(iv));
            }
            else
            {
                iv2.from(p);
                ref=iv2;
                camellia_decrypt( iv2.u.buf, ws->key1, tmp.u.buf );
                tmp.op_xor(iv);
                assert(!ref.equals(tmp));
                tmp.to(p);
                iv = iv2;
            }
        }
    }

    /* return (void *) ws; */
    pthread_exit((void *) ws);
    return NULL; /* pro forma */
}


/* ************************************************************************ */
/* ************************************************************************ */
/* ************************************************************************ */


static void keyprep(const char *raw, int rawkeysize, KeyTableType *key1, KeyTableType *key2)
{
    struct whirlpool wp;
    uint8_t digest[WHIRLPOOL_DIGESTBYTES];

    if(rawkeysize<=0)
        rawkeysize = strlen(raw);

    whirlpool_init(&wp);
    whirlpool_add(&wp, (const uint8_t * const) raw, rawkeysize*8);
    whirlpool_finalize(&wp, digest);
    /*
    fputs("KEY=", stderr);
    for(int i=0; i<WHIRLPOOL_DIGESTBYTES; i++)
        fprintf(stderr, "%02x", digest[i]);
    fputc('\n', stderr);
    */
    camellia_ekeygen( digest, key1 );
    camellia_ekeygen( digest+WHIRLPOOL_DIGESTBYTES/2, key2 );
}


/* ************************************************************************ */
/* ************************************************************************ */
/* ************************************************************************ */


