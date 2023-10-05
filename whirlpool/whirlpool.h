/*
 * whirlpool.h
 */


#define WHIRLPOOL_DIGESTBYTES 64
#define WHIRLPOOL_DIGESTBITS  (8*WHIRLPOOL_DIGESTBYTES) /* 512 */

#define WHIRLPOOL_WBLOCKBYTES 64
#define WHIRLPOOL_WBLOCKBITS  (8*WHIRLPOOL_WBLOCKBYTES) /* 512 */

#define WHIRLPOOL_LENGTHBYTES 32
#define WHIRLPOOL_LENGTHBITS  (8*WHIRLPOOL_LENGTHBYTES) /* 256 */


struct whirlpool
{
/* private: */
    uint8_t  bitLength[WHIRLPOOL_LENGTHBYTES]; /* global number of hashed bits (256-bit counter) */
    uint8_t  buffer[WHIRLPOOL_WBLOCKBYTES];    /* buffer of data to hash */
    int64_t  bufferBits;             /* current number of bits on the buffer */
    int64_t  bufferPos;              /* current (possibly incomplete) byte slot on the buffer */
    uint64_t hash[WHIRLPOOL_DIGESTBYTES/8];    /* the hashing state */
    uint8_t  hexhash[WHIRLPOOL_DIGESTBYTES*2+1];
};


/* void whirlpool_processbuffer(struct whirlpool *wp); */
void whirlpool_init(struct whirlpool *wp);
void whirlpool_add(struct whirlpool *wp, const uint8_t * const source, unsigned long sourceBits);
void whirlpool_finalize(struct whirlpool *wp, uint8_t * const result);
const uint8_t *whirlpool_hexhash(struct whirlpool *wp);
