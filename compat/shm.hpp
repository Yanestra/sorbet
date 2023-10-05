
#include "sotpet_shm.h"


class SotpetSharedMem
    {
        protected:
            uint64_t        id;
            int             shmf = -1;
            size_t          buflen;
            void           *buf = NULL;
            char            shmfnbuf[SHM_NAME_SIZE];

        public:
                            SotpetSharedMem(uint64_t id, size_t sz, bool cr=true);
                            SotpetSharedMem(uint64_t id, void *buf, size_t sz);
                           ~SotpetSharedMem();
            uint8_t        *getbuf();
            uint64_t        getid();
    };
