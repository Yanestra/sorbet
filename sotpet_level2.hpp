
/* SOTPET - Simple One-Trick Pony Encryption Tool */


/* ATTENTION! This function calls perror() directly and will only return 0 if no error eccured. */

/* ifi=-1 ofi=-1 slots=1 */


int            sotpet_f2f_smart(bool encflg, int ifi, int ofi, int cpus, uint32_t numblocks, uint32_t blocksize, bool usetrailer, struct trailerset *trailer, void *sotpet);



