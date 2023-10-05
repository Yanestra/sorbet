
/* SOTPET - Simple One-Trick Pony Encryption Tool */

extern const uint8_t sotpet_magic_plain[];
extern const uint8_t sotpet_magic_enc[];
extern const uint8_t sotpet_magic2_plain[];
extern const uint8_t sotpet_magic2_enc[];

#define MAGICSIZE 8
#define MAGICSIZE2 4
#define HASHSIZE WHIRLPOOL_DIGESTBYTES
#define OURVERSION 1


#define OFFMAGIC2 (MAGICSIZE+4)

#define PLAINTEXT_TRAILERSIZE (4+MAGICSIZE+MAGICSIZE2)
#define ENCRYPTED_TRAILERSIZE (12+HASHSIZE+4+MAGICSIZE+MAGICSIZE2)


struct plaintext_trailer
  {
    uint8_t  magic[MAGICSIZE];
    uint16_t version;
    uint16_t trailersize;
    uint8_t  magic2[MAGICSIZE2];
  };

struct encrypted_trailer
  {
    uint8_t  magic[MAGICSIZE];
    uint16_t version;
    uint16_t trailersize;
    uint8_t  magic2[MAGICSIZE2];
    uint8_t  hash[HASHSIZE];
    uint64_t filesize;
    uint64_t ctime;         /* << this should be the creation_time in the BSD sense */
    uint64_t mtime;

    //uint8_t  padding[128-ENCRYPTED_TRAILERSIZE];
  };

struct trailerset
  {
    struct plaintext_trailer pln;
    struct encrypted_trailer enc;
    uint8_t                  hash[HASHSIZE];
  };


#define TRAILERPADDING sizeof(struct encrypted_trailer)
