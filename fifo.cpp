

/* SOTPET - Simple One-Trick Pony Encryption Tool */

#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "fifo.hpp"


/*
class BufSet
    {
        public:

            uint8_t            *buf;
            int32_t             buflen;
            int32_t             reqdpos;
*/

            BufSet::BufSet(const uint8_t *magic, int32_t magiclen, int32_t pos)
{
    this->buf = new uint8_t[magiclen];
    memcpy(this->buf, magic, magiclen);
    this->buflen = magiclen;
    this->reqdpos = pos;
}


            BufSet::~BufSet()
{
    //delete this->buf;
}


/*
class FIFO
    {
        protected:

            uint8_t            *buf;
            int32_t             buflen;
            int32_t             rptr;
            int32_t             wptr;
*/

                FIFO::FIFO(uint32_t len)
{
    this->buf = new uint8_t[len];
    this->buflen = len;
    this->rptr = 0;
    this->wptr = 0;
}


void            FIFO::reset()
{
    this->rptr = 0;
    this->wptr = 0;
}


                FIFO::~FIFO()
{
    delete this->buf;
}


int32_t         FIFO::push(const uint8_t *inbuf, int32_t inbuflen)
{
    int32_t n=0;

    while(inbuflen--) { this->push(*inbuf++); n++; }
    return n;
}


void            FIFO::push(uint8_t c)
{
    int32_t oldwptr;

    this->buf[this->wptr] = c;
    oldwptr = this->wptr;
    this->wptr = (this->wptr+1) % this->buflen;
    /* if full, just overwrite */
    /* if(oldwptr==rptr) do nothing */
    if((oldwptr==this->buflen-1 && this->rptr==0) || (this->rptr==oldwptr+1))
        this->rptr = (this->wptr+1) % this->buflen;
    /* wptr pulls rptr behind */
}


int32_t         FIFO::pop(uint8_t *outbuf, int32_t outbuflen)
{
    int16_t c;
    int32_t n=0;

    while(outbuflen-- > 0)
    {
        c = this->pop();
        if(c<0)
            break;
        *outbuf++=c;
        n++;
    }
    return n;
}


int32_t         FIFO::mcpy(uint8_t *outbuf, int32_t outbuflen, int32_t off)
{
    int32_t n=0;

    off = (off + this->rptr) % this->buflen;
    while(outbuflen-- > 0)
    {
        *outbuf++ = this->buf[off];
        n++;
    }
    return n;
}


int16_t         FIFO::pop()
{
    int16_t r;
    if(this->wptr==this->rptr)
        return -1;
    r = this->buf[this->rptr];
    this->rptr = (this->rptr+1) % this->buflen;
    return r;
}


void            FIFO::pop(int32_t poplen)
{
    //this->rptr = (this->rptr+poplen) % this->buflen;
    while(poplen-- > 0 && this->rptr != this->wptr)
        this->rptr = (this->rptr+1) % this->buflen;
}


int32_t         FIFO::getvlen()
{
    if(this->wptr >= this->rptr)
        return this->wptr - this->rptr;
    return this->wptr - this->rptr + this->buflen;
}


uint8_t         FIFO::getvbyte(int32_t p)
{
    p = (p + this->rptr) % this->buflen;
    return this->buf[p];
}


void            FIFO::putvbyte(uint8_t c, int32_t p)
{
    p = (p + this->rptr) % this->buflen;
    this->buf[p] = c;
}


bool            FIFO::checkmagic(const uint8_t *needle, int32_t needlelen, int32_t off /* =0 */)
{
    int32_t rp = (this->rptr + off) % this->buflen;

    while(needlelen>0 && *needle == this->buf[rp])
    {
        needlelen--;
        needle++;
        rp = (rp + 1) % this->buflen;
    }
    return !needlelen;
}


/*
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
*/

int32_t         FIFO::findmagicbackwards(const uint8_t *needle, int32_t needlelen, int32_t haystacklen /* =0 */)
{
    int32_t i,j;

    if(haystacklen==0)
        haystacklen = this->getvlen();
    else
        if(haystacklen<0)
            haystacklen = this->getvlen()+haystacklen+1;   /* haystacklen is negative, so blen-haystacklen+1 */

    for(i=haystacklen-needlelen; i>=0; i--)
    {
        for(j=0; j<(int32_t)needlelen; j++)
        {
            if(needle[j]!=this->getvbyte(i+j))
                break;
        }
        if(j>=(int32_t)needlelen)
            return (i>=this->rptr) ? (i-this->rptr) : (i-this->rptr+this->buflen);
    }
    return -1;
}


int32_t         FIFO::getp(int32_t rel /* =-1 */)
{
    if(rel==-1)
        return this->rptr;
    rel = this->rptr - rel;
    if(rel<0)
        rel += this->buflen;
    return rel;
}


void            FIFO::registermagic_reset()
{
    this->mg.clear();
}


void            FIFO::registermagic_add(const uint8_t *needle, int32_t needlelen, int32_t reqdpos)
{
    this->mg.push_back(BufSet(needle, needlelen, reqdpos));
}


void            FIFO::registermagic_setsize(uint32_t sz)
{
    this->wslen = sz;
}

bool            FIFO::registermagic_detect()
{
    if(this->mg.empty())
        return false;
    for (std::vector<BufSet>::iterator i = this->mg.begin(); i != this->mg.end(); ++i)
    {
        for(int n=0; n<i->buflen; n++)
            if(this->getvbyte(i->reqdpos + n) != i->buf[n])
                return false;
    }
    return true;
}


void            FIFO::registermagic_wsget(uint8_t *ws, int32_t wslen /* =0 */)
{
    if(wslen==0)
        wslen = this->wslen;

    for(int n=0; n<wslen; n++)
        ws[n] = this->getvbyte(n);
}


#include <cstdio>


void            FIFO::dump(int32_t mx, int32_t my /* =INT32_MAX */)
{
    fprintf(stderr, "rptr=%d wptr=%d buflen=%d\n", this->rptr, this->wptr, this->buflen);
    for(int y=0; y<my; y++)
    {
        int dy = y*mx;
        fprintf(stderr, "%04x  ", dy);
        for(int x=0; x<mx; x++)
        {
            int dx = dy+x;
            if(dx>this->getvlen())
                goto b2;
            fprintf(stderr, "%02x ", this->getvbyte(dy+x));
        }
        fputc('\n', stderr);
    }
  b2:
    fputc('\n', stderr);
}


