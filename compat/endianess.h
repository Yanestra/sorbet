

#if BYTEORDER=='L'

#define UINT16_COMPAT(x) (x)

#define UINT32_COMPAT(x) (x)

#define UINT64_COMPAT(x) (x)

#elif BYTEORDER=='B'

#define UINT16_COMPAT(x) ((((uint16_t)(x)>>8) & UINT8_C(0xff)) | ((uint16_t)((x) & UINT8_C(0xff))<<8))

#define UINT32_COMPAT(x) (((uint32_t)UINT16_COMPAT((uint32_t)(x)>>16) & UINT16_C(0xffff)) | ((uint32_t)UINT16_COMPAT((x) & UINT16_C(0xffff))<<16))

#define UINT64_COMPAT(x) (((uint64_t)UINT32_COMPAT((uint64_t)(x)>>32) & UINT32_C(0xffffffff)) | ((uint64_t)UINT32_COMPAT((x) & UINT32_C(0xffffffff))<<32))

#else
#error this should not happen
#endif

/// 01 23 45 67
/// 10 32 54 76
/// 32 10 76 54
/// 76 54 32 10

/*
 * I tested this with different versions of gcc, and appears, version 13.2.1 (x86_64)
 * is ok while 7.5 (NetBSD/SPARC32) produces defective code.
 *
 * This reminds of the old times when you had to bitmask-out each and every shifting
 * operation even though there shouldn't be any extra bits remaining in the bit size
 * of the casted value.  I guess that was a K&R thing recasting every value to int
 * if that makes sense or not.
 *
 * The code as it is seems to work but I know that situation can be fragile.
 *
 */
