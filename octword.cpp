
/* SOTPET - Simple One-Trick Pony Encryption Tool */

#include <stdio.h>     // iostream is crap
#include <stdint.h>
#include <string.h>

#include "octword.hpp"



/*
 * Unlike camellia.c, this implementation is smallendian.
 * And, camellia.c uses __builtin_bswap32().
 */



/*
    x = 2^64 * xh + xl
    y = 2^64 * yh + yl
    so x * y = (2^128 * xh * yh) + (2^64 * xh * yl) + (2^64 * yh * xl) + (yl * xl)

    subtract the overflow from the result
    from this result subtract the overflow again
    if a*b==0 then return 1-a-b
*/


void OctWord::op_xor(const OctWord &operand)
{
    this->u.n.ql ^= operand.u.n.ql;
    this->u.n.qh ^= operand.u.n.qh;
}


bool OctWord::equals(const OctWord &operand)
{
    return this->u.n.ql == operand.u.n.ql && this->u.n.qh == operand.u.n.qh;
}


OctWord *OctWord::dup()
{
    OctWord *res = new OctWord();
    res->u.n.ql = this->u.n.ql;
    res->u.n.qh = this->u.n.qh;
    return res;
}


bool OctWord::nonzero()
{
    return this->u.n.ql || this->u.n.qh;
}


void OctWord::from(uint64_t lo, uint64_t hi)
{
#if BYTEORDER=='L'
    this->u.n.ql = lo;
    this->u.n.qh = hi;
#elif BYTEORDER=='B'
    this->u.buf[15] = (uint8_t) (hi >> 56);
    this->u.buf[14] = (uint8_t) (hi >> 48);
    this->u.buf[13] = (uint8_t) (hi >> 40);
    this->u.buf[12] = (uint8_t) (hi >> 32);
    this->u.buf[11] = (uint8_t) (hi >> 24);
    this->u.buf[10] = (uint8_t) (hi >> 16);
    this->u.buf[9] = (uint8_t) (hi >> 8);
    this->u.buf[8] = (uint8_t) (hi);
    this->u.buf[7] = (uint8_t) (lo >> 56);
    this->u.buf[6] = (uint8_t) (lo >> 48);
    this->u.buf[5] = (uint8_t) (lo >> 40);
    this->u.buf[4] = (uint8_t) (lo >> 32);
    this->u.buf[3] = (uint8_t) (lo >> 24);
    this->u.buf[2] = (uint8_t) (lo >> 16);
    this->u.buf[1] = (uint8_t) (lo >> 8);
    this->u.buf[0] = (uint8_t) (lo);
#else
#error this should not happen
#endif
}


void OctWord::from(const uint8_t *buf)
{
// #if BYTEORDER=='L'
    memcpy(this->u.buf, buf, 128/8);
// #elif BYTEORDER=='B'
//     this->u.buf[0] = buf[15];
//     this->u.buf[1] = buf[14];
//     this->u.buf[2] = buf[13];
//     this->u.buf[3] = buf[12];
//     this->u.buf[4] = buf[11];
//     this->u.buf[5] = buf[10];
//     this->u.buf[6] = buf[9];
//     this->u.buf[7] = buf[8];
//     this->u.buf[8] = buf[7];
//     this->u.buf[9] = buf[6];
//     this->u.buf[10] = buf[5];
//     this->u.buf[11] = buf[4];
//     this->u.buf[12] = buf[3];
//     this->u.buf[13] = buf[2];
//     this->u.buf[14] = buf[1];
//     this->u.buf[15] = buf[0];
// #else
// #error this should not happen
// #endif
}


void OctWord::to(uint8_t *buf)
{
// #if BYTEORDER=='L'
    memcpy(buf, this->u.buf, 128/8);
// #elif BYTEORDER=='B'
//     buf[0] = this->u.buf[15];
//     buf[1] = this->u.buf[14];
//     buf[2] = this->u.buf[13];
//     buf[3] = this->u.buf[12];
//     buf[4] = this->u.buf[11];
//     buf[5] = this->u.buf[10];
//     buf[6] = this->u.buf[9];
//     buf[7] = this->u.buf[8];
//     buf[8] = this->u.buf[7];
//     buf[9] = this->u.buf[6];
//     buf[10] = this->u.buf[5];
//     buf[11] = this->u.buf[4];
//     buf[12] = this->u.buf[3];
//     buf[13] = this->u.buf[2];
//     buf[14] = this->u.buf[1];
//     buf[15] = this->u.buf[0];
// #else
// #error this should not happen
// #endif
}


void OctWord::print(FILE *f)
{
    int i;
    for(i=15; i>=0; i--)
        fprintf(f, "%02x", (unsigned) this->u.buf[i]);
}
