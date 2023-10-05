
/* SOTPET - Simple One-Trick Pony Encryption Tool */


class OctWord
    {
        public:
            union
                {
                    struct { uint64_t ql, qh; } n;
                    uint8_t                     buf[16];
                } u;

            void op_xor(const OctWord &operand);
            bool equals(const OctWord &operand);
            void from(uint64_t lo, uint64_t hi);
            void from(const uint8_t *buf);
            void to(uint8_t *buf);
            OctWord *dup();
            bool nonzero();

            void print(FILE *f);

            static unsigned mysize() {return 128;}
    };

