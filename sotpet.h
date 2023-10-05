
/* SOTPET - Simple One-Trick Pony Encryption Tool */


#ifndef __cplusplus
typedef short bool;
#endif

/* keysize=0 */

void          *sotpet_init(uint16_t cpus, const char *fun, const char *pass, uint16_t keysize, uint32_t blocksize, uint64_t startblocknum, bool decryptflag);

int            sotpet_add_blockset(void *wk, uint32_t numblocks, uint32_t blocksize, uint8_t *bufferptr);

int            sotpet_process(void *wk);

void           sotpet_release(void *wk);

int            sotpet_exit(void *wk);



/* static void keyprep(const char *raw, int rawkeysize, uint8_t **key1, uint8_t **key2); */



