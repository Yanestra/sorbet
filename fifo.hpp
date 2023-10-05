
/* SOTPET - Simple One-Trick Pony Encryption Tool */

#include <vector>


class BufSet
    {
        public:

            uint8_t            *buf;
            int32_t             buflen;
            int32_t             reqdpos;

            BufSet(const uint8_t *magic, int32_t magiclen, int32_t pos);
            ~BufSet();
    };


class FIFO
    {
        protected:

            uint8_t            *buf;
            int32_t             buflen;
            int32_t             rptr;
            int32_t             wptr;

            std::vector<BufSet> mg;
            int32_t             wslen;

        public:

            FIFO(uint32_t len);
            ~FIFO();

            int32_t         push(const uint8_t *inbuf, int32_t inbuflen);
            void            push(uint8_t c);
            int32_t         pop(uint8_t *outbuf, int32_t outbuflen);
            int16_t         pop();
            void            pop(int32_t poplen);

            int32_t         getvlen();
            uint8_t         getvbyte(int32_t p);
            void            putvbyte(uint8_t c, int32_t p);

            bool            checkmagic(const uint8_t *needle, int32_t needlelen, int32_t off=0);

            int32_t         findmagicbackwards(const uint8_t *needle, int32_t needlelen, int32_t haystacklen=0);

            int32_t         mcpy(uint8_t *outbuf, int32_t outbuflen, int32_t off);

            void            reset();

            int32_t         getp(int32_t rel=-1);

            void            registermagic_reset();
            void            registermagic_add(const uint8_t *needle, int32_t needlelen, int32_t reqdpos);
            void            registermagic_setsize(uint32_t sz);

            bool            registermagic_detect();
            void            registermagic_wsget(uint8_t *ws, int32_t wslen=0);

            void            dump(int32_t mx, int32_t my=INT32_MAX);
    };
