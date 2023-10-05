
/* SOTPET - Simple One-Trick Pony Encryption Tool */


extern uint64_t current_blockid;


struct sotpet_workset;


struct sotpet_container
  {
    const char             *fun;
    bool                    decryptflag;
    uint16_t                cpus;
    uint16_t                slots;
    struct sotpet_workset  *workset;
    uint32_t                blocksize;
    uint64_t                startblocknum;
    uint64_t                currentblocknum;
    uint16_t                slot;

    /***********************************/

  //uint8_t                 hash[WHIRLPOOL_DIGESTBYTES];
    KeyTableType           *nshkey1,
                           *nshkey2;
    SotpetSharedMem        *shkey1,
                           *shkey2;
  //uint64_t                hashbytes;
  };


struct sotpet_workset
  {
    bool                    decryptflag;

    /***********************************/

    uint32_t                numblocks;
    uint32_t                blocksize;
    uint32_t                startblocknum;
    uint8_t                *bufferptr;

    /***********************************/

    KeyTableType           *key1,            // just references, do not free()
                           *key2;
  };
