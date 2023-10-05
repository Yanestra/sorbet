/* camellia.c ver 1.2.0
 *
 * Copyright (c) 2006,2007
 * NTT (Nippon Telegraph and Telephone Corporation) . All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer as
 *   the first lines of this file unmodified.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NTT ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL NTT BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Algorithm Specification 
 *  http://info.isl.ntt.co.jp/crypt/eng/camellia/specifications.html
 */


#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "camellia.h"

/* key constants */

#define CAMELLIA_SIGMA1L UINT32_C(0xA09E667F)
#define CAMELLIA_SIGMA1R UINT32_C(0x3BCC908B)
#define CAMELLIA_SIGMA2L UINT32_C(0xB67AE858)
#define CAMELLIA_SIGMA2R UINT32_C(0x4CAA73B2)
#define CAMELLIA_SIGMA3L UINT32_C(0xC6EF372F)
#define CAMELLIA_SIGMA3R UINT32_C(0xE94F82BE)
#define CAMELLIA_SIGMA4L UINT32_C(0x54FF53A5)
#define CAMELLIA_SIGMA4R UINT32_C(0xF1D36F1C)
#define CAMELLIA_SIGMA5L UINT32_C(0x10E527FA)
#define CAMELLIA_SIGMA5R UINT32_C(0xDE682D1D)
#define CAMELLIA_SIGMA6L UINT32_C(0xB05688C2)
#define CAMELLIA_SIGMA6R UINT32_C(0xB3E6C1FD)

/*
 *  macros
 */


#ifdef __GNUC__

typedef uint32_t uint32_t_unaligned __attribute__((aligned(1), may_alias));

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define SWAP(x) __builtin_bswap32(x)
#else
#  define SWAP(x) (x)
# endif

# define GETU32(p) SWAP(*((uint32_t_unaligned *)(p)))
# define PUTU32(ct, st) ({*((uint32_t_unaligned *)(ct)) = SWAP((st));})

#elif defined(_MSC_VER)

# define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
# define GETU32(p) SWAP(*((uint32_t *)(p)))
# define PUTU32(ct, st) {*((uint32_t *)(ct)) = SWAP((st));}

#else /* not MS-VC */

# define GETU32(pt)				\
    (((uint32_t)(pt)[0] << 24)			\
     ^ ((uint32_t)(pt)[1] << 16)			\
     ^ ((uint32_t)(pt)[2] <<  8)			\
     ^ ((uint32_t)(pt)[3]))

# define PUTU32(ct, st)  {			\
	(ct)[0] = (uint8_t)((st) >> 24);		\
	(ct)[1] = (uint8_t)((st) >> 16);		\
	(ct)[2] = (uint8_t)((st) >>  8);		\
	(ct)[3] = (uint8_t)(st); }

#endif

#define CamelliaSubkeyL(INDEX) (subkey[(INDEX)*2])
#define CamelliaSubkeyR(INDEX) (subkey[(INDEX)*2 + 1])

/* rotation right shift 1byte */
#define CAMELLIA_RR8(x) (((x) >> 8) + ((x) << 24))
/* rotation left shift 1bit */
#define CAMELLIA_RL1(x) (((x) << 1) + ((x) >> 31))
/* rotation left shift 1byte */
#define CAMELLIA_RL8(x) (((x) << 8) + ((x) >> 24))

#define CAMELLIA_ROLDQ(ll, lr, rl, rr, w0, w1, bits)	\
    do {						\
	w0 = ll;					\
	ll = (ll << bits) + (lr >> (32 - bits));	\
	lr = (lr << bits) + (rl >> (32 - bits));	\
	rl = (rl << bits) + (rr >> (32 - bits));	\
	rr = (rr << bits) + (w0 >> (32 - bits));	\
    } while(0)

#define CAMELLIA_ROLDQo32(ll, lr, rl, rr, w0, w1, bits)	\
    do {						\
	w0 = ll;					\
	w1 = lr;					\
	ll = (lr << (bits - 32)) + (rl >> (64 - bits));	\
	lr = (rl << (bits - 32)) + (rr >> (64 - bits));	\
	rl = (rr << (bits - 32)) + (w0 >> (64 - bits));	\
	rr = (w0 << (bits - 32)) + (w1 >> (64 - bits));	\
    } while(0)

#define CAMELLIA_SP1110(INDEX) (camellia_sp1110[(INDEX)])
#define CAMELLIA_SP0222(INDEX) (camellia_sp0222[(INDEX)])
#define CAMELLIA_SP3033(INDEX) (camellia_sp3033[(INDEX)])
#define CAMELLIA_SP4404(INDEX) (camellia_sp4404[(INDEX)])

#define CAMELLIA_F(xl, xr, kl, kr, yl, yr, il, ir, t0, t1)	\
    do {							\
	il = xl ^ kl;						\
	ir = xr ^ kr;						\
	t0 = il >> 16;						\
	t1 = ir >> 16;						\
	yl = CAMELLIA_SP1110(ir & 0xff)				\
	    ^ CAMELLIA_SP0222((t1 >> 8) & 0xff)			\
	    ^ CAMELLIA_SP3033(t1 & 0xff)			\
	    ^ CAMELLIA_SP4404((ir >> 8) & 0xff);		\
	yr = CAMELLIA_SP1110((t0 >> 8) & 0xff)			\
	    ^ CAMELLIA_SP0222(t0 & 0xff)			\
	    ^ CAMELLIA_SP3033((il >> 8) & 0xff)			\
	    ^ CAMELLIA_SP4404(il & 0xff);			\
	yl ^= yr;						\
	yr = CAMELLIA_RR8(yr);					\
	yr ^= yl;						\
    } while(0)


/*
 * for speed up
 *
 */
#define CAMELLIA_FLS(ll, lr, rl, rr, kll, klr, krl, krr, t0, t1, t2, t3) \
    do {								\
	t0 = kll;							\
	t0 &= ll;							\
	lr ^= CAMELLIA_RL1(t0);						\
	t1 = klr;							\
	t1 |= lr;							\
	ll ^= t1;							\
									\
	t2 = krr;							\
	t2 |= rr;							\
	rl ^= t2;							\
	t3 = krl;							\
	t3 &= rl;							\
	rr ^= CAMELLIA_RL1(t3);						\
    } while(0)

#define CAMELLIA_ROUNDSM(xl, xr, kl, kr, yl, yr, il, ir, t0, t1)	\
    do {								\
	ir = CAMELLIA_SP1110(xr & 0xff)					\
	    ^ CAMELLIA_SP0222((xr >> 24) & 0xff)			\
	    ^ CAMELLIA_SP3033((xr >> 16) & 0xff)			\
	    ^ CAMELLIA_SP4404((xr >> 8) & 0xff);			\
	il = CAMELLIA_SP1110((xl >> 24) & 0xff)				\
	    ^ CAMELLIA_SP0222((xl >> 16) & 0xff)			\
	    ^ CAMELLIA_SP3033((xl >> 8) & 0xff)				\
	    ^ CAMELLIA_SP4404(xl & 0xff);				\
	il ^= kl;							\
	ir ^= kr;							\
	ir ^= il;							\
	il = CAMELLIA_RR8(il);						\
	il ^= ir;							\
	yl ^= ir;							\
	yr ^= il;							\
    } while(0)


static const uint32_t camellia_sp1110[256] = {
    UINT32_C(0x70707000),UINT32_C(0x82828200),UINT32_C(0x2c2c2c00),UINT32_C(0xececec00),
    UINT32_C(0xb3b3b300),UINT32_C(0x27272700),UINT32_C(0xc0c0c000),UINT32_C(0xe5e5e500),
    UINT32_C(0xe4e4e400),UINT32_C(0x85858500),UINT32_C(0x57575700),UINT32_C(0x35353500),
    UINT32_C(0xeaeaea00),UINT32_C(0x0c0c0c00),UINT32_C(0xaeaeae00),UINT32_C(0x41414100),
    UINT32_C(0x23232300),UINT32_C(0xefefef00),UINT32_C(0x6b6b6b00),UINT32_C(0x93939300),
    UINT32_C(0x45454500),UINT32_C(0x19191900),UINT32_C(0xa5a5a500),UINT32_C(0x21212100),
    UINT32_C(0xededed00),UINT32_C(0x0e0e0e00),UINT32_C(0x4f4f4f00),UINT32_C(0x4e4e4e00),
    UINT32_C(0x1d1d1d00),UINT32_C(0x65656500),UINT32_C(0x92929200),UINT32_C(0xbdbdbd00),
    UINT32_C(0x86868600),UINT32_C(0xb8b8b800),UINT32_C(0xafafaf00),UINT32_C(0x8f8f8f00),
    UINT32_C(0x7c7c7c00),UINT32_C(0xebebeb00),UINT32_C(0x1f1f1f00),UINT32_C(0xcecece00),
    UINT32_C(0x3e3e3e00),UINT32_C(0x30303000),UINT32_C(0xdcdcdc00),UINT32_C(0x5f5f5f00),
    UINT32_C(0x5e5e5e00),UINT32_C(0xc5c5c500),UINT32_C(0x0b0b0b00),UINT32_C(0x1a1a1a00),
    UINT32_C(0xa6a6a600),UINT32_C(0xe1e1e100),UINT32_C(0x39393900),UINT32_C(0xcacaca00),
    UINT32_C(0xd5d5d500),UINT32_C(0x47474700),UINT32_C(0x5d5d5d00),UINT32_C(0x3d3d3d00),
    UINT32_C(0xd9d9d900),UINT32_C(0x01010100),UINT32_C(0x5a5a5a00),UINT32_C(0xd6d6d600),
    UINT32_C(0x51515100),UINT32_C(0x56565600),UINT32_C(0x6c6c6c00),UINT32_C(0x4d4d4d00),
    UINT32_C(0x8b8b8b00),UINT32_C(0x0d0d0d00),UINT32_C(0x9a9a9a00),UINT32_C(0x66666600),
    UINT32_C(0xfbfbfb00),UINT32_C(0xcccccc00),UINT32_C(0xb0b0b000),UINT32_C(0x2d2d2d00),
    UINT32_C(0x74747400),UINT32_C(0x12121200),UINT32_C(0x2b2b2b00),UINT32_C(0x20202000),
    UINT32_C(0xf0f0f000),UINT32_C(0xb1b1b100),UINT32_C(0x84848400),UINT32_C(0x99999900),
    UINT32_C(0xdfdfdf00),UINT32_C(0x4c4c4c00),UINT32_C(0xcbcbcb00),UINT32_C(0xc2c2c200),
    UINT32_C(0x34343400),UINT32_C(0x7e7e7e00),UINT32_C(0x76767600),UINT32_C(0x05050500),
    UINT32_C(0x6d6d6d00),UINT32_C(0xb7b7b700),UINT32_C(0xa9a9a900),UINT32_C(0x31313100),
    UINT32_C(0xd1d1d100),UINT32_C(0x17171700),UINT32_C(0x04040400),UINT32_C(0xd7d7d700),
    UINT32_C(0x14141400),UINT32_C(0x58585800),UINT32_C(0x3a3a3a00),UINT32_C(0x61616100),
    UINT32_C(0xdedede00),UINT32_C(0x1b1b1b00),UINT32_C(0x11111100),UINT32_C(0x1c1c1c00),
    UINT32_C(0x32323200),UINT32_C(0x0f0f0f00),UINT32_C(0x9c9c9c00),UINT32_C(0x16161600),
    UINT32_C(0x53535300),UINT32_C(0x18181800),UINT32_C(0xf2f2f200),UINT32_C(0x22222200),
    UINT32_C(0xfefefe00),UINT32_C(0x44444400),UINT32_C(0xcfcfcf00),UINT32_C(0xb2b2b200),
    UINT32_C(0xc3c3c300),UINT32_C(0xb5b5b500),UINT32_C(0x7a7a7a00),UINT32_C(0x91919100),
    UINT32_C(0x24242400),UINT32_C(0x08080800),UINT32_C(0xe8e8e800),UINT32_C(0xa8a8a800),
    UINT32_C(0x60606000),UINT32_C(0xfcfcfc00),UINT32_C(0x69696900),UINT32_C(0x50505000),
    UINT32_C(0xaaaaaa00),UINT32_C(0xd0d0d000),UINT32_C(0xa0a0a000),UINT32_C(0x7d7d7d00),
    UINT32_C(0xa1a1a100),UINT32_C(0x89898900),UINT32_C(0x62626200),UINT32_C(0x97979700),
    UINT32_C(0x54545400),UINT32_C(0x5b5b5b00),UINT32_C(0x1e1e1e00),UINT32_C(0x95959500),
    UINT32_C(0xe0e0e000),UINT32_C(0xffffff00),UINT32_C(0x64646400),UINT32_C(0xd2d2d200),
    UINT32_C(0x10101000),UINT32_C(0xc4c4c400),UINT32_C(0x00000000),UINT32_C(0x48484800),
    UINT32_C(0xa3a3a300),UINT32_C(0xf7f7f700),UINT32_C(0x75757500),UINT32_C(0xdbdbdb00),
    UINT32_C(0x8a8a8a00),UINT32_C(0x03030300),UINT32_C(0xe6e6e600),UINT32_C(0xdadada00),
    UINT32_C(0x09090900),UINT32_C(0x3f3f3f00),UINT32_C(0xdddddd00),UINT32_C(0x94949400),
    UINT32_C(0x87878700),UINT32_C(0x5c5c5c00),UINT32_C(0x83838300),UINT32_C(0x02020200),
    UINT32_C(0xcdcdcd00),UINT32_C(0x4a4a4a00),UINT32_C(0x90909000),UINT32_C(0x33333300),
    UINT32_C(0x73737300),UINT32_C(0x67676700),UINT32_C(0xf6f6f600),UINT32_C(0xf3f3f300),
    UINT32_C(0x9d9d9d00),UINT32_C(0x7f7f7f00),UINT32_C(0xbfbfbf00),UINT32_C(0xe2e2e200),
    UINT32_C(0x52525200),UINT32_C(0x9b9b9b00),UINT32_C(0xd8d8d800),UINT32_C(0x26262600),
    UINT32_C(0xc8c8c800),UINT32_C(0x37373700),UINT32_C(0xc6c6c600),UINT32_C(0x3b3b3b00),
    UINT32_C(0x81818100),UINT32_C(0x96969600),UINT32_C(0x6f6f6f00),UINT32_C(0x4b4b4b00),
    UINT32_C(0x13131300),UINT32_C(0xbebebe00),UINT32_C(0x63636300),UINT32_C(0x2e2e2e00),
    UINT32_C(0xe9e9e900),UINT32_C(0x79797900),UINT32_C(0xa7a7a700),UINT32_C(0x8c8c8c00),
    UINT32_C(0x9f9f9f00),UINT32_C(0x6e6e6e00),UINT32_C(0xbcbcbc00),UINT32_C(0x8e8e8e00),
    UINT32_C(0x29292900),UINT32_C(0xf5f5f500),UINT32_C(0xf9f9f900),UINT32_C(0xb6b6b600),
    UINT32_C(0x2f2f2f00),UINT32_C(0xfdfdfd00),UINT32_C(0xb4b4b400),UINT32_C(0x59595900),
    UINT32_C(0x78787800),UINT32_C(0x98989800),UINT32_C(0x06060600),UINT32_C(0x6a6a6a00),
    UINT32_C(0xe7e7e700),UINT32_C(0x46464600),UINT32_C(0x71717100),UINT32_C(0xbababa00),
    UINT32_C(0xd4d4d400),UINT32_C(0x25252500),UINT32_C(0xababab00),UINT32_C(0x42424200),
    UINT32_C(0x88888800),UINT32_C(0xa2a2a200),UINT32_C(0x8d8d8d00),UINT32_C(0xfafafa00),
    UINT32_C(0x72727200),UINT32_C(0x07070700),UINT32_C(0xb9b9b900),UINT32_C(0x55555500),
    UINT32_C(0xf8f8f800),UINT32_C(0xeeeeee00),UINT32_C(0xacacac00),UINT32_C(0x0a0a0a00),
    UINT32_C(0x36363600),UINT32_C(0x49494900),UINT32_C(0x2a2a2a00),UINT32_C(0x68686800),
    UINT32_C(0x3c3c3c00),UINT32_C(0x38383800),UINT32_C(0xf1f1f100),UINT32_C(0xa4a4a400),
    UINT32_C(0x40404000),UINT32_C(0x28282800),UINT32_C(0xd3d3d300),UINT32_C(0x7b7b7b00),
    UINT32_C(0xbbbbbb00),UINT32_C(0xc9c9c900),UINT32_C(0x43434300),UINT32_C(0xc1c1c100),
    UINT32_C(0x15151500),UINT32_C(0xe3e3e300),UINT32_C(0xadadad00),UINT32_C(0xf4f4f400),
    UINT32_C(0x77777700),UINT32_C(0xc7c7c700),UINT32_C(0x80808000),UINT32_C(0x9e9e9e00),
};

static const uint32_t camellia_sp0222[256] = {
    UINT32_C(0x00e0e0e0),UINT32_C(0x00050505),UINT32_C(0x00585858),UINT32_C(0x00d9d9d9),
    UINT32_C(0x00676767),UINT32_C(0x004e4e4e),UINT32_C(0x00818181),UINT32_C(0x00cbcbcb),
    UINT32_C(0x00c9c9c9),UINT32_C(0x000b0b0b),UINT32_C(0x00aeaeae),UINT32_C(0x006a6a6a),
    UINT32_C(0x00d5d5d5),UINT32_C(0x00181818),UINT32_C(0x005d5d5d),UINT32_C(0x00828282),
    UINT32_C(0x00464646),UINT32_C(0x00dfdfdf),UINT32_C(0x00d6d6d6),UINT32_C(0x00272727),
    UINT32_C(0x008a8a8a),UINT32_C(0x00323232),UINT32_C(0x004b4b4b),UINT32_C(0x00424242),
    UINT32_C(0x00dbdbdb),UINT32_C(0x001c1c1c),UINT32_C(0x009e9e9e),UINT32_C(0x009c9c9c),
    UINT32_C(0x003a3a3a),UINT32_C(0x00cacaca),UINT32_C(0x00252525),UINT32_C(0x007b7b7b),
    UINT32_C(0x000d0d0d),UINT32_C(0x00717171),UINT32_C(0x005f5f5f),UINT32_C(0x001f1f1f),
    UINT32_C(0x00f8f8f8),UINT32_C(0x00d7d7d7),UINT32_C(0x003e3e3e),UINT32_C(0x009d9d9d),
    UINT32_C(0x007c7c7c),UINT32_C(0x00606060),UINT32_C(0x00b9b9b9),UINT32_C(0x00bebebe),
    UINT32_C(0x00bcbcbc),UINT32_C(0x008b8b8b),UINT32_C(0x00161616),UINT32_C(0x00343434),
    UINT32_C(0x004d4d4d),UINT32_C(0x00c3c3c3),UINT32_C(0x00727272),UINT32_C(0x00959595),
    UINT32_C(0x00ababab),UINT32_C(0x008e8e8e),UINT32_C(0x00bababa),UINT32_C(0x007a7a7a),
    UINT32_C(0x00b3b3b3),UINT32_C(0x00020202),UINT32_C(0x00b4b4b4),UINT32_C(0x00adadad),
    UINT32_C(0x00a2a2a2),UINT32_C(0x00acacac),UINT32_C(0x00d8d8d8),UINT32_C(0x009a9a9a),
    UINT32_C(0x00171717),UINT32_C(0x001a1a1a),UINT32_C(0x00353535),UINT32_C(0x00cccccc),
    UINT32_C(0x00f7f7f7),UINT32_C(0x00999999),UINT32_C(0x00616161),UINT32_C(0x005a5a5a),
    UINT32_C(0x00e8e8e8),UINT32_C(0x00242424),UINT32_C(0x00565656),UINT32_C(0x00404040),
    UINT32_C(0x00e1e1e1),UINT32_C(0x00636363),UINT32_C(0x00090909),UINT32_C(0x00333333),
    UINT32_C(0x00bfbfbf),UINT32_C(0x00989898),UINT32_C(0x00979797),UINT32_C(0x00858585),
    UINT32_C(0x00686868),UINT32_C(0x00fcfcfc),UINT32_C(0x00ececec),UINT32_C(0x000a0a0a),
    UINT32_C(0x00dadada),UINT32_C(0x006f6f6f),UINT32_C(0x00535353),UINT32_C(0x00626262),
    UINT32_C(0x00a3a3a3),UINT32_C(0x002e2e2e),UINT32_C(0x00080808),UINT32_C(0x00afafaf),
    UINT32_C(0x00282828),UINT32_C(0x00b0b0b0),UINT32_C(0x00747474),UINT32_C(0x00c2c2c2),
    UINT32_C(0x00bdbdbd),UINT32_C(0x00363636),UINT32_C(0x00222222),UINT32_C(0x00383838),
    UINT32_C(0x00646464),UINT32_C(0x001e1e1e),UINT32_C(0x00393939),UINT32_C(0x002c2c2c),
    UINT32_C(0x00a6a6a6),UINT32_C(0x00303030),UINT32_C(0x00e5e5e5),UINT32_C(0x00444444),
    UINT32_C(0x00fdfdfd),UINT32_C(0x00888888),UINT32_C(0x009f9f9f),UINT32_C(0x00656565),
    UINT32_C(0x00878787),UINT32_C(0x006b6b6b),UINT32_C(0x00f4f4f4),UINT32_C(0x00232323),
    UINT32_C(0x00484848),UINT32_C(0x00101010),UINT32_C(0x00d1d1d1),UINT32_C(0x00515151),
    UINT32_C(0x00c0c0c0),UINT32_C(0x00f9f9f9),UINT32_C(0x00d2d2d2),UINT32_C(0x00a0a0a0),
    UINT32_C(0x00555555),UINT32_C(0x00a1a1a1),UINT32_C(0x00414141),UINT32_C(0x00fafafa),
    UINT32_C(0x00434343),UINT32_C(0x00131313),UINT32_C(0x00c4c4c4),UINT32_C(0x002f2f2f),
    UINT32_C(0x00a8a8a8),UINT32_C(0x00b6b6b6),UINT32_C(0x003c3c3c),UINT32_C(0x002b2b2b),
    UINT32_C(0x00c1c1c1),UINT32_C(0x00ffffff),UINT32_C(0x00c8c8c8),UINT32_C(0x00a5a5a5),
    UINT32_C(0x00202020),UINT32_C(0x00898989),UINT32_C(0x00000000),UINT32_C(0x00909090),
    UINT32_C(0x00474747),UINT32_C(0x00efefef),UINT32_C(0x00eaeaea),UINT32_C(0x00b7b7b7),
    UINT32_C(0x00151515),UINT32_C(0x00060606),UINT32_C(0x00cdcdcd),UINT32_C(0x00b5b5b5),
    UINT32_C(0x00121212),UINT32_C(0x007e7e7e),UINT32_C(0x00bbbbbb),UINT32_C(0x00292929),
    UINT32_C(0x000f0f0f),UINT32_C(0x00b8b8b8),UINT32_C(0x00070707),UINT32_C(0x00040404),
    UINT32_C(0x009b9b9b),UINT32_C(0x00949494),UINT32_C(0x00212121),UINT32_C(0x00666666),
    UINT32_C(0x00e6e6e6),UINT32_C(0x00cecece),UINT32_C(0x00ededed),UINT32_C(0x00e7e7e7),
    UINT32_C(0x003b3b3b),UINT32_C(0x00fefefe),UINT32_C(0x007f7f7f),UINT32_C(0x00c5c5c5),
    UINT32_C(0x00a4a4a4),UINT32_C(0x00373737),UINT32_C(0x00b1b1b1),UINT32_C(0x004c4c4c),
    UINT32_C(0x00919191),UINT32_C(0x006e6e6e),UINT32_C(0x008d8d8d),UINT32_C(0x00767676),
    UINT32_C(0x00030303),UINT32_C(0x002d2d2d),UINT32_C(0x00dedede),UINT32_C(0x00969696),
    UINT32_C(0x00262626),UINT32_C(0x007d7d7d),UINT32_C(0x00c6c6c6),UINT32_C(0x005c5c5c),
    UINT32_C(0x00d3d3d3),UINT32_C(0x00f2f2f2),UINT32_C(0x004f4f4f),UINT32_C(0x00191919),
    UINT32_C(0x003f3f3f),UINT32_C(0x00dcdcdc),UINT32_C(0x00797979),UINT32_C(0x001d1d1d),
    UINT32_C(0x00525252),UINT32_C(0x00ebebeb),UINT32_C(0x00f3f3f3),UINT32_C(0x006d6d6d),
    UINT32_C(0x005e5e5e),UINT32_C(0x00fbfbfb),UINT32_C(0x00696969),UINT32_C(0x00b2b2b2),
    UINT32_C(0x00f0f0f0),UINT32_C(0x00313131),UINT32_C(0x000c0c0c),UINT32_C(0x00d4d4d4),
    UINT32_C(0x00cfcfcf),UINT32_C(0x008c8c8c),UINT32_C(0x00e2e2e2),UINT32_C(0x00757575),
    UINT32_C(0x00a9a9a9),UINT32_C(0x004a4a4a),UINT32_C(0x00575757),UINT32_C(0x00848484),
    UINT32_C(0x00111111),UINT32_C(0x00454545),UINT32_C(0x001b1b1b),UINT32_C(0x00f5f5f5),
    UINT32_C(0x00e4e4e4),UINT32_C(0x000e0e0e),UINT32_C(0x00737373),UINT32_C(0x00aaaaaa),
    UINT32_C(0x00f1f1f1),UINT32_C(0x00dddddd),UINT32_C(0x00595959),UINT32_C(0x00141414),
    UINT32_C(0x006c6c6c),UINT32_C(0x00929292),UINT32_C(0x00545454),UINT32_C(0x00d0d0d0),
    UINT32_C(0x00787878),UINT32_C(0x00707070),UINT32_C(0x00e3e3e3),UINT32_C(0x00494949),
    UINT32_C(0x00808080),UINT32_C(0x00505050),UINT32_C(0x00a7a7a7),UINT32_C(0x00f6f6f6),
    UINT32_C(0x00777777),UINT32_C(0x00939393),UINT32_C(0x00868686),UINT32_C(0x00838383),
    UINT32_C(0x002a2a2a),UINT32_C(0x00c7c7c7),UINT32_C(0x005b5b5b),UINT32_C(0x00e9e9e9),
    UINT32_C(0x00eeeeee),UINT32_C(0x008f8f8f),UINT32_C(0x00010101),UINT32_C(0x003d3d3d),
};

static const uint32_t camellia_sp3033[256] = {
    UINT32_C(0x38003838),UINT32_C(0x41004141),UINT32_C(0x16001616),UINT32_C(0x76007676),
    UINT32_C(0xd900d9d9),UINT32_C(0x93009393),UINT32_C(0x60006060),UINT32_C(0xf200f2f2),
    UINT32_C(0x72007272),UINT32_C(0xc200c2c2),UINT32_C(0xab00abab),UINT32_C(0x9a009a9a),
    UINT32_C(0x75007575),UINT32_C(0x06000606),UINT32_C(0x57005757),UINT32_C(0xa000a0a0),
    UINT32_C(0x91009191),UINT32_C(0xf700f7f7),UINT32_C(0xb500b5b5),UINT32_C(0xc900c9c9),
    UINT32_C(0xa200a2a2),UINT32_C(0x8c008c8c),UINT32_C(0xd200d2d2),UINT32_C(0x90009090),
    UINT32_C(0xf600f6f6),UINT32_C(0x07000707),UINT32_C(0xa700a7a7),UINT32_C(0x27002727),
    UINT32_C(0x8e008e8e),UINT32_C(0xb200b2b2),UINT32_C(0x49004949),UINT32_C(0xde00dede),
    UINT32_C(0x43004343),UINT32_C(0x5c005c5c),UINT32_C(0xd700d7d7),UINT32_C(0xc700c7c7),
    UINT32_C(0x3e003e3e),UINT32_C(0xf500f5f5),UINT32_C(0x8f008f8f),UINT32_C(0x67006767),
    UINT32_C(0x1f001f1f),UINT32_C(0x18001818),UINT32_C(0x6e006e6e),UINT32_C(0xaf00afaf),
    UINT32_C(0x2f002f2f),UINT32_C(0xe200e2e2),UINT32_C(0x85008585),UINT32_C(0x0d000d0d),
    UINT32_C(0x53005353),UINT32_C(0xf000f0f0),UINT32_C(0x9c009c9c),UINT32_C(0x65006565),
    UINT32_C(0xea00eaea),UINT32_C(0xa300a3a3),UINT32_C(0xae00aeae),UINT32_C(0x9e009e9e),
    UINT32_C(0xec00ecec),UINT32_C(0x80008080),UINT32_C(0x2d002d2d),UINT32_C(0x6b006b6b),
    UINT32_C(0xa800a8a8),UINT32_C(0x2b002b2b),UINT32_C(0x36003636),UINT32_C(0xa600a6a6),
    UINT32_C(0xc500c5c5),UINT32_C(0x86008686),UINT32_C(0x4d004d4d),UINT32_C(0x33003333),
    UINT32_C(0xfd00fdfd),UINT32_C(0x66006666),UINT32_C(0x58005858),UINT32_C(0x96009696),
    UINT32_C(0x3a003a3a),UINT32_C(0x09000909),UINT32_C(0x95009595),UINT32_C(0x10001010),
    UINT32_C(0x78007878),UINT32_C(0xd800d8d8),UINT32_C(0x42004242),UINT32_C(0xcc00cccc),
    UINT32_C(0xef00efef),UINT32_C(0x26002626),UINT32_C(0xe500e5e5),UINT32_C(0x61006161),
    UINT32_C(0x1a001a1a),UINT32_C(0x3f003f3f),UINT32_C(0x3b003b3b),UINT32_C(0x82008282),
    UINT32_C(0xb600b6b6),UINT32_C(0xdb00dbdb),UINT32_C(0xd400d4d4),UINT32_C(0x98009898),
    UINT32_C(0xe800e8e8),UINT32_C(0x8b008b8b),UINT32_C(0x02000202),UINT32_C(0xeb00ebeb),
    UINT32_C(0x0a000a0a),UINT32_C(0x2c002c2c),UINT32_C(0x1d001d1d),UINT32_C(0xb000b0b0),
    UINT32_C(0x6f006f6f),UINT32_C(0x8d008d8d),UINT32_C(0x88008888),UINT32_C(0x0e000e0e),
    UINT32_C(0x19001919),UINT32_C(0x87008787),UINT32_C(0x4e004e4e),UINT32_C(0x0b000b0b),
    UINT32_C(0xa900a9a9),UINT32_C(0x0c000c0c),UINT32_C(0x79007979),UINT32_C(0x11001111),
    UINT32_C(0x7f007f7f),UINT32_C(0x22002222),UINT32_C(0xe700e7e7),UINT32_C(0x59005959),
    UINT32_C(0xe100e1e1),UINT32_C(0xda00dada),UINT32_C(0x3d003d3d),UINT32_C(0xc800c8c8),
    UINT32_C(0x12001212),UINT32_C(0x04000404),UINT32_C(0x74007474),UINT32_C(0x54005454),
    UINT32_C(0x30003030),UINT32_C(0x7e007e7e),UINT32_C(0xb400b4b4),UINT32_C(0x28002828),
    UINT32_C(0x55005555),UINT32_C(0x68006868),UINT32_C(0x50005050),UINT32_C(0xbe00bebe),
    UINT32_C(0xd000d0d0),UINT32_C(0xc400c4c4),UINT32_C(0x31003131),UINT32_C(0xcb00cbcb),
    UINT32_C(0x2a002a2a),UINT32_C(0xad00adad),UINT32_C(0x0f000f0f),UINT32_C(0xca00caca),
    UINT32_C(0x70007070),UINT32_C(0xff00ffff),UINT32_C(0x32003232),UINT32_C(0x69006969),
    UINT32_C(0x08000808),UINT32_C(0x62006262),UINT32_C(0x00000000),UINT32_C(0x24002424),
    UINT32_C(0xd100d1d1),UINT32_C(0xfb00fbfb),UINT32_C(0xba00baba),UINT32_C(0xed00eded),
    UINT32_C(0x45004545),UINT32_C(0x81008181),UINT32_C(0x73007373),UINT32_C(0x6d006d6d),
    UINT32_C(0x84008484),UINT32_C(0x9f009f9f),UINT32_C(0xee00eeee),UINT32_C(0x4a004a4a),
    UINT32_C(0xc300c3c3),UINT32_C(0x2e002e2e),UINT32_C(0xc100c1c1),UINT32_C(0x01000101),
    UINT32_C(0xe600e6e6),UINT32_C(0x25002525),UINT32_C(0x48004848),UINT32_C(0x99009999),
    UINT32_C(0xb900b9b9),UINT32_C(0xb300b3b3),UINT32_C(0x7b007b7b),UINT32_C(0xf900f9f9),
    UINT32_C(0xce00cece),UINT32_C(0xbf00bfbf),UINT32_C(0xdf00dfdf),UINT32_C(0x71007171),
    UINT32_C(0x29002929),UINT32_C(0xcd00cdcd),UINT32_C(0x6c006c6c),UINT32_C(0x13001313),
    UINT32_C(0x64006464),UINT32_C(0x9b009b9b),UINT32_C(0x63006363),UINT32_C(0x9d009d9d),
    UINT32_C(0xc000c0c0),UINT32_C(0x4b004b4b),UINT32_C(0xb700b7b7),UINT32_C(0xa500a5a5),
    UINT32_C(0x89008989),UINT32_C(0x5f005f5f),UINT32_C(0xb100b1b1),UINT32_C(0x17001717),
    UINT32_C(0xf400f4f4),UINT32_C(0xbc00bcbc),UINT32_C(0xd300d3d3),UINT32_C(0x46004646),
    UINT32_C(0xcf00cfcf),UINT32_C(0x37003737),UINT32_C(0x5e005e5e),UINT32_C(0x47004747),
    UINT32_C(0x94009494),UINT32_C(0xfa00fafa),UINT32_C(0xfc00fcfc),UINT32_C(0x5b005b5b),
    UINT32_C(0x97009797),UINT32_C(0xfe00fefe),UINT32_C(0x5a005a5a),UINT32_C(0xac00acac),
    UINT32_C(0x3c003c3c),UINT32_C(0x4c004c4c),UINT32_C(0x03000303),UINT32_C(0x35003535),
    UINT32_C(0xf300f3f3),UINT32_C(0x23002323),UINT32_C(0xb800b8b8),UINT32_C(0x5d005d5d),
    UINT32_C(0x6a006a6a),UINT32_C(0x92009292),UINT32_C(0xd500d5d5),UINT32_C(0x21002121),
    UINT32_C(0x44004444),UINT32_C(0x51005151),UINT32_C(0xc600c6c6),UINT32_C(0x7d007d7d),
    UINT32_C(0x39003939),UINT32_C(0x83008383),UINT32_C(0xdc00dcdc),UINT32_C(0xaa00aaaa),
    UINT32_C(0x7c007c7c),UINT32_C(0x77007777),UINT32_C(0x56005656),UINT32_C(0x05000505),
    UINT32_C(0x1b001b1b),UINT32_C(0xa400a4a4),UINT32_C(0x15001515),UINT32_C(0x34003434),
    UINT32_C(0x1e001e1e),UINT32_C(0x1c001c1c),UINT32_C(0xf800f8f8),UINT32_C(0x52005252),
    UINT32_C(0x20002020),UINT32_C(0x14001414),UINT32_C(0xe900e9e9),UINT32_C(0xbd00bdbd),
    UINT32_C(0xdd00dddd),UINT32_C(0xe400e4e4),UINT32_C(0xa100a1a1),UINT32_C(0xe000e0e0),
    UINT32_C(0x8a008a8a),UINT32_C(0xf100f1f1),UINT32_C(0xd600d6d6),UINT32_C(0x7a007a7a),
    UINT32_C(0xbb00bbbb),UINT32_C(0xe300e3e3),UINT32_C(0x40004040),UINT32_C(0x4f004f4f),
};

static const uint32_t camellia_sp4404[256] = {
    UINT32_C(0x70700070),UINT32_C(0x2c2c002c),UINT32_C(0xb3b300b3),UINT32_C(0xc0c000c0),
    UINT32_C(0xe4e400e4),UINT32_C(0x57570057),UINT32_C(0xeaea00ea),UINT32_C(0xaeae00ae),
    UINT32_C(0x23230023),UINT32_C(0x6b6b006b),UINT32_C(0x45450045),UINT32_C(0xa5a500a5),
    UINT32_C(0xeded00ed),UINT32_C(0x4f4f004f),UINT32_C(0x1d1d001d),UINT32_C(0x92920092),
    UINT32_C(0x86860086),UINT32_C(0xafaf00af),UINT32_C(0x7c7c007c),UINT32_C(0x1f1f001f),
    UINT32_C(0x3e3e003e),UINT32_C(0xdcdc00dc),UINT32_C(0x5e5e005e),UINT32_C(0x0b0b000b),
    UINT32_C(0xa6a600a6),UINT32_C(0x39390039),UINT32_C(0xd5d500d5),UINT32_C(0x5d5d005d),
    UINT32_C(0xd9d900d9),UINT32_C(0x5a5a005a),UINT32_C(0x51510051),UINT32_C(0x6c6c006c),
    UINT32_C(0x8b8b008b),UINT32_C(0x9a9a009a),UINT32_C(0xfbfb00fb),UINT32_C(0xb0b000b0),
    UINT32_C(0x74740074),UINT32_C(0x2b2b002b),UINT32_C(0xf0f000f0),UINT32_C(0x84840084),
    UINT32_C(0xdfdf00df),UINT32_C(0xcbcb00cb),UINT32_C(0x34340034),UINT32_C(0x76760076),
    UINT32_C(0x6d6d006d),UINT32_C(0xa9a900a9),UINT32_C(0xd1d100d1),UINT32_C(0x04040004),
    UINT32_C(0x14140014),UINT32_C(0x3a3a003a),UINT32_C(0xdede00de),UINT32_C(0x11110011),
    UINT32_C(0x32320032),UINT32_C(0x9c9c009c),UINT32_C(0x53530053),UINT32_C(0xf2f200f2),
    UINT32_C(0xfefe00fe),UINT32_C(0xcfcf00cf),UINT32_C(0xc3c300c3),UINT32_C(0x7a7a007a),
    UINT32_C(0x24240024),UINT32_C(0xe8e800e8),UINT32_C(0x60600060),UINT32_C(0x69690069),
    UINT32_C(0xaaaa00aa),UINT32_C(0xa0a000a0),UINT32_C(0xa1a100a1),UINT32_C(0x62620062),
    UINT32_C(0x54540054),UINT32_C(0x1e1e001e),UINT32_C(0xe0e000e0),UINT32_C(0x64640064),
    UINT32_C(0x10100010),UINT32_C(0x00000000),UINT32_C(0xa3a300a3),UINT32_C(0x75750075),
    UINT32_C(0x8a8a008a),UINT32_C(0xe6e600e6),UINT32_C(0x09090009),UINT32_C(0xdddd00dd),
    UINT32_C(0x87870087),UINT32_C(0x83830083),UINT32_C(0xcdcd00cd),UINT32_C(0x90900090),
    UINT32_C(0x73730073),UINT32_C(0xf6f600f6),UINT32_C(0x9d9d009d),UINT32_C(0xbfbf00bf),
    UINT32_C(0x52520052),UINT32_C(0xd8d800d8),UINT32_C(0xc8c800c8),UINT32_C(0xc6c600c6),
    UINT32_C(0x81810081),UINT32_C(0x6f6f006f),UINT32_C(0x13130013),UINT32_C(0x63630063),
    UINT32_C(0xe9e900e9),UINT32_C(0xa7a700a7),UINT32_C(0x9f9f009f),UINT32_C(0xbcbc00bc),
    UINT32_C(0x29290029),UINT32_C(0xf9f900f9),UINT32_C(0x2f2f002f),UINT32_C(0xb4b400b4),
    UINT32_C(0x78780078),UINT32_C(0x06060006),UINT32_C(0xe7e700e7),UINT32_C(0x71710071),
    UINT32_C(0xd4d400d4),UINT32_C(0xabab00ab),UINT32_C(0x88880088),UINT32_C(0x8d8d008d),
    UINT32_C(0x72720072),UINT32_C(0xb9b900b9),UINT32_C(0xf8f800f8),UINT32_C(0xacac00ac),
    UINT32_C(0x36360036),UINT32_C(0x2a2a002a),UINT32_C(0x3c3c003c),UINT32_C(0xf1f100f1),
    UINT32_C(0x40400040),UINT32_C(0xd3d300d3),UINT32_C(0xbbbb00bb),UINT32_C(0x43430043),
    UINT32_C(0x15150015),UINT32_C(0xadad00ad),UINT32_C(0x77770077),UINT32_C(0x80800080),
    UINT32_C(0x82820082),UINT32_C(0xecec00ec),UINT32_C(0x27270027),UINT32_C(0xe5e500e5),
    UINT32_C(0x85850085),UINT32_C(0x35350035),UINT32_C(0x0c0c000c),UINT32_C(0x41410041),
    UINT32_C(0xefef00ef),UINT32_C(0x93930093),UINT32_C(0x19190019),UINT32_C(0x21210021),
    UINT32_C(0x0e0e000e),UINT32_C(0x4e4e004e),UINT32_C(0x65650065),UINT32_C(0xbdbd00bd),
    UINT32_C(0xb8b800b8),UINT32_C(0x8f8f008f),UINT32_C(0xebeb00eb),UINT32_C(0xcece00ce),
    UINT32_C(0x30300030),UINT32_C(0x5f5f005f),UINT32_C(0xc5c500c5),UINT32_C(0x1a1a001a),
    UINT32_C(0xe1e100e1),UINT32_C(0xcaca00ca),UINT32_C(0x47470047),UINT32_C(0x3d3d003d),
    UINT32_C(0x01010001),UINT32_C(0xd6d600d6),UINT32_C(0x56560056),UINT32_C(0x4d4d004d),
    UINT32_C(0x0d0d000d),UINT32_C(0x66660066),UINT32_C(0xcccc00cc),UINT32_C(0x2d2d002d),
    UINT32_C(0x12120012),UINT32_C(0x20200020),UINT32_C(0xb1b100b1),UINT32_C(0x99990099),
    UINT32_C(0x4c4c004c),UINT32_C(0xc2c200c2),UINT32_C(0x7e7e007e),UINT32_C(0x05050005),
    UINT32_C(0xb7b700b7),UINT32_C(0x31310031),UINT32_C(0x17170017),UINT32_C(0xd7d700d7),
    UINT32_C(0x58580058),UINT32_C(0x61610061),UINT32_C(0x1b1b001b),UINT32_C(0x1c1c001c),
    UINT32_C(0x0f0f000f),UINT32_C(0x16160016),UINT32_C(0x18180018),UINT32_C(0x22220022),
    UINT32_C(0x44440044),UINT32_C(0xb2b200b2),UINT32_C(0xb5b500b5),UINT32_C(0x91910091),
    UINT32_C(0x08080008),UINT32_C(0xa8a800a8),UINT32_C(0xfcfc00fc),UINT32_C(0x50500050),
    UINT32_C(0xd0d000d0),UINT32_C(0x7d7d007d),UINT32_C(0x89890089),UINT32_C(0x97970097),
    UINT32_C(0x5b5b005b),UINT32_C(0x95950095),UINT32_C(0xffff00ff),UINT32_C(0xd2d200d2),
    UINT32_C(0xc4c400c4),UINT32_C(0x48480048),UINT32_C(0xf7f700f7),UINT32_C(0xdbdb00db),
    UINT32_C(0x03030003),UINT32_C(0xdada00da),UINT32_C(0x3f3f003f),UINT32_C(0x94940094),
    UINT32_C(0x5c5c005c),UINT32_C(0x02020002),UINT32_C(0x4a4a004a),UINT32_C(0x33330033),
    UINT32_C(0x67670067),UINT32_C(0xf3f300f3),UINT32_C(0x7f7f007f),UINT32_C(0xe2e200e2),
    UINT32_C(0x9b9b009b),UINT32_C(0x26260026),UINT32_C(0x37370037),UINT32_C(0x3b3b003b),
    UINT32_C(0x96960096),UINT32_C(0x4b4b004b),UINT32_C(0xbebe00be),UINT32_C(0x2e2e002e),
    UINT32_C(0x79790079),UINT32_C(0x8c8c008c),UINT32_C(0x6e6e006e),UINT32_C(0x8e8e008e),
    UINT32_C(0xf5f500f5),UINT32_C(0xb6b600b6),UINT32_C(0xfdfd00fd),UINT32_C(0x59590059),
    UINT32_C(0x98980098),UINT32_C(0x6a6a006a),UINT32_C(0x46460046),UINT32_C(0xbaba00ba),
    UINT32_C(0x25250025),UINT32_C(0x42420042),UINT32_C(0xa2a200a2),UINT32_C(0xfafa00fa),
    UINT32_C(0x07070007),UINT32_C(0x55550055),UINT32_C(0xeeee00ee),UINT32_C(0x0a0a000a),
    UINT32_C(0x49490049),UINT32_C(0x68680068),UINT32_C(0x38380038),UINT32_C(0xa4a400a4),
    UINT32_C(0x28280028),UINT32_C(0x7b7b007b),UINT32_C(0xc9c900c9),UINT32_C(0xc1c100c1),
    UINT32_C(0xe3e300e3),UINT32_C(0xf4f400f4),UINT32_C(0xc7c700c7),UINT32_C(0x9e9e009e),
};


/**
 * Stuff related to the Camellia key schedule
 */
#define subl(x) subL[(x)]
#define subr(x) subR[(x)]

static void camellia_setup128(const unsigned char *key, uint32_t *subkey)
{
    uint32_t kll, klr, krl, krr;
    uint32_t il, ir, t0, t1, w0, w1;
    uint32_t kw4l, kw4r, dw, tl, tr;
    uint32_t subL[26];
    uint32_t subR[26];

    /**
     *  k == kll || klr || krl || krr (|| is concatination)
     */
    kll = GETU32(key     );
    klr = GETU32(key +  4);
    krl = GETU32(key +  8);
    krr = GETU32(key + 12);
    /**
     * generate KL dependent subkeys
     */
    subl(0) = kll; subr(0) = klr;
    subl(1) = krl; subr(1) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(4) = kll; subr(4) = klr;
    subl(5) = krl; subr(5) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 30);
    subl(10) = kll; subr(10) = klr;
    subl(11) = krl; subr(11) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(13) = krl; subr(13) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(16) = kll; subr(16) = klr;
    subl(17) = krl; subr(17) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(18) = kll; subr(18) = klr;
    subl(19) = krl; subr(19) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(22) = kll; subr(22) = klr;
    subl(23) = krl; subr(23) = krr;

    /* generate KA */
    kll = subl(0); klr = subr(0);
    krl = subl(1); krr = subr(1);
    CAMELLIA_F(kll, klr,
	       CAMELLIA_SIGMA1L, CAMELLIA_SIGMA1R,
	       w0, w1, il, ir, t0, t1);
    krl ^= w0; krr ^= w1;
    CAMELLIA_F(krl, krr,
	       CAMELLIA_SIGMA2L, CAMELLIA_SIGMA2R,
	       kll, klr, il, ir, t0, t1);
    CAMELLIA_F(kll, klr,
	       CAMELLIA_SIGMA3L, CAMELLIA_SIGMA3R,
	       krl, krr, il, ir, t0, t1);
    krl ^= w0; krr ^= w1;
    CAMELLIA_F(krl, krr,
	       CAMELLIA_SIGMA4L, CAMELLIA_SIGMA4R,
	       w0, w1, il, ir, t0, t1);
    kll ^= w0; klr ^= w1;

    /* generate KA dependent subkeys */
    subl(2) = kll; subr(2) = klr;
    subl(3) = krl; subr(3) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(6) = kll; subr(6) = klr;
    subl(7) = krl; subr(7) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(8) = kll; subr(8) = klr;
    subl(9) = krl; subr(9) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(12) = kll; subr(12) = klr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(14) = kll; subr(14) = klr;
    subl(15) = krl; subr(15) = krr;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 34);
    subl(20) = kll; subr(20) = klr;
    subl(21) = krl; subr(21) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(24) = kll; subr(24) = klr;
    subl(25) = krl; subr(25) = krr;


    /* absorb kw2 to other subkeys */
    subl(3) ^= subl(1); subr(3) ^= subr(1);
    subl(5) ^= subl(1); subr(5) ^= subr(1);
    subl(7) ^= subl(1); subr(7) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(9);
    dw = subl(1) & subl(9), subr(1) ^= CAMELLIA_RL1(dw);
    subl(11) ^= subl(1); subr(11) ^= subr(1);
    subl(13) ^= subl(1); subr(13) ^= subr(1);
    subl(15) ^= subl(1); subr(15) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(17);
    dw = subl(1) & subl(17), subr(1) ^= CAMELLIA_RL1(dw);
    subl(19) ^= subl(1); subr(19) ^= subr(1);
    subl(21) ^= subl(1); subr(21) ^= subr(1);
    subl(23) ^= subl(1); subr(23) ^= subr(1);
    subl(24) ^= subl(1); subr(24) ^= subr(1);

    /* absorb kw4 to other subkeys */
    kw4l = subl(25); kw4r = subr(25);
    subl(22) ^= kw4l; subr(22) ^= kw4r;
    subl(20) ^= kw4l; subr(20) ^= kw4r;
    subl(18) ^= kw4l; subr(18) ^= kw4r;
    kw4l ^= kw4r & ~subr(16);
    dw = kw4l & subl(16), kw4r ^= CAMELLIA_RL1(dw);
    subl(14) ^= kw4l; subr(14) ^= kw4r;
    subl(12) ^= kw4l; subr(12) ^= kw4r;
    subl(10) ^= kw4l; subr(10) ^= kw4r;
    kw4l ^= kw4r & ~subr(8);
    dw = kw4l & subl(8), kw4r ^= CAMELLIA_RL1(dw);
    subl(6) ^= kw4l; subr(6) ^= kw4r;
    subl(4) ^= kw4l; subr(4) ^= kw4r;
    subl(2) ^= kw4l; subr(2) ^= kw4r;
    subl(0) ^= kw4l; subr(0) ^= kw4r;

    /* key XOR is end of F-function */
    CamelliaSubkeyL(0) = subl(0) ^ subl(2);
    CamelliaSubkeyR(0) = subr(0) ^ subr(2);
    CamelliaSubkeyL(2) = subl(3);
    CamelliaSubkeyR(2) = subr(3);
    CamelliaSubkeyL(3) = subl(2) ^ subl(4);
    CamelliaSubkeyR(3) = subr(2) ^ subr(4);
    CamelliaSubkeyL(4) = subl(3) ^ subl(5);
    CamelliaSubkeyR(4) = subr(3) ^ subr(5);
    CamelliaSubkeyL(5) = subl(4) ^ subl(6);
    CamelliaSubkeyR(5) = subr(4) ^ subr(6);
    CamelliaSubkeyL(6) = subl(5) ^ subl(7);
    CamelliaSubkeyR(6) = subr(5) ^ subr(7);
    tl = subl(10) ^ (subr(10) & ~subr(8));
    dw = tl & subl(8), tr = subr(10) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(7) = subl(6) ^ tl;
    CamelliaSubkeyR(7) = subr(6) ^ tr;
    CamelliaSubkeyL(8) = subl(8);
    CamelliaSubkeyR(8) = subr(8);
    CamelliaSubkeyL(9) = subl(9);
    CamelliaSubkeyR(9) = subr(9);
    tl = subl(7) ^ (subr(7) & ~subr(9));
    dw = tl & subl(9), tr = subr(7) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(10) = tl ^ subl(11);
    CamelliaSubkeyR(10) = tr ^ subr(11);
    CamelliaSubkeyL(11) = subl(10) ^ subl(12);
    CamelliaSubkeyR(11) = subr(10) ^ subr(12);
    CamelliaSubkeyL(12) = subl(11) ^ subl(13);
    CamelliaSubkeyR(12) = subr(11) ^ subr(13);
    CamelliaSubkeyL(13) = subl(12) ^ subl(14);
    CamelliaSubkeyR(13) = subr(12) ^ subr(14);
    CamelliaSubkeyL(14) = subl(13) ^ subl(15);
    CamelliaSubkeyR(14) = subr(13) ^ subr(15);
    tl = subl(18) ^ (subr(18) & ~subr(16));
    dw = tl & subl(16),	tr = subr(18) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(15) = subl(14) ^ tl;
    CamelliaSubkeyR(15) = subr(14) ^ tr;
    CamelliaSubkeyL(16) = subl(16);
    CamelliaSubkeyR(16) = subr(16);
    CamelliaSubkeyL(17) = subl(17);
    CamelliaSubkeyR(17) = subr(17);
    tl = subl(15) ^ (subr(15) & ~subr(17));
    dw = tl & subl(17),	tr = subr(15) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(18) = tl ^ subl(19);
    CamelliaSubkeyR(18) = tr ^ subr(19);
    CamelliaSubkeyL(19) = subl(18) ^ subl(20);
    CamelliaSubkeyR(19) = subr(18) ^ subr(20);
    CamelliaSubkeyL(20) = subl(19) ^ subl(21);
    CamelliaSubkeyR(20) = subr(19) ^ subr(21);
    CamelliaSubkeyL(21) = subl(20) ^ subl(22);
    CamelliaSubkeyR(21) = subr(20) ^ subr(22);
    CamelliaSubkeyL(22) = subl(21) ^ subl(23);
    CamelliaSubkeyR(22) = subr(21) ^ subr(23);
    CamelliaSubkeyL(23) = subl(22);
    CamelliaSubkeyR(23) = subr(22);
    CamelliaSubkeyL(24) = subl(24) ^ subl(23);
    CamelliaSubkeyR(24) = subr(24) ^ subr(23);

    /* apply the inverse of the last half of P-function */
    dw = CamelliaSubkeyL(2) ^ CamelliaSubkeyR(2), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(2) = CamelliaSubkeyL(2) ^ dw, CamelliaSubkeyL(2) = dw;
    dw = CamelliaSubkeyL(3) ^ CamelliaSubkeyR(3), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(3) = CamelliaSubkeyL(3) ^ dw, CamelliaSubkeyL(3) = dw;
    dw = CamelliaSubkeyL(4) ^ CamelliaSubkeyR(4), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(4) = CamelliaSubkeyL(4) ^ dw, CamelliaSubkeyL(4) = dw;
    dw = CamelliaSubkeyL(5) ^ CamelliaSubkeyR(5), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(5) = CamelliaSubkeyL(5) ^ dw, CamelliaSubkeyL(5) = dw;
    dw = CamelliaSubkeyL(6) ^ CamelliaSubkeyR(6), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(6) = CamelliaSubkeyL(6) ^ dw, CamelliaSubkeyL(6) = dw;
    dw = CamelliaSubkeyL(7) ^ CamelliaSubkeyR(7), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(7) = CamelliaSubkeyL(7) ^ dw, CamelliaSubkeyL(7) = dw;
    dw = CamelliaSubkeyL(10) ^ CamelliaSubkeyR(10), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(10) = CamelliaSubkeyL(10) ^ dw, CamelliaSubkeyL(10) = dw;
    dw = CamelliaSubkeyL(11) ^ CamelliaSubkeyR(11), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(11) = CamelliaSubkeyL(11) ^ dw, CamelliaSubkeyL(11) = dw;
    dw = CamelliaSubkeyL(12) ^ CamelliaSubkeyR(12), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(12) = CamelliaSubkeyL(12) ^ dw, CamelliaSubkeyL(12) = dw;
    dw = CamelliaSubkeyL(13) ^ CamelliaSubkeyR(13), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(13) = CamelliaSubkeyL(13) ^ dw, CamelliaSubkeyL(13) = dw;
    dw = CamelliaSubkeyL(14) ^ CamelliaSubkeyR(14), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(14) = CamelliaSubkeyL(14) ^ dw, CamelliaSubkeyL(14) = dw;
    dw = CamelliaSubkeyL(15) ^ CamelliaSubkeyR(15), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(15) = CamelliaSubkeyL(15) ^ dw, CamelliaSubkeyL(15) = dw;
    dw = CamelliaSubkeyL(18) ^ CamelliaSubkeyR(18), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(18) = CamelliaSubkeyL(18) ^ dw, CamelliaSubkeyL(18) = dw;
    dw = CamelliaSubkeyL(19) ^ CamelliaSubkeyR(19), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(19) = CamelliaSubkeyL(19) ^ dw, CamelliaSubkeyL(19) = dw;
    dw = CamelliaSubkeyL(20) ^ CamelliaSubkeyR(20), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(20) = CamelliaSubkeyL(20) ^ dw, CamelliaSubkeyL(20) = dw;
    dw = CamelliaSubkeyL(21) ^ CamelliaSubkeyR(21), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(21) = CamelliaSubkeyL(21) ^ dw, CamelliaSubkeyL(21) = dw;
    dw = CamelliaSubkeyL(22) ^ CamelliaSubkeyR(22), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(22) = CamelliaSubkeyL(22) ^ dw, CamelliaSubkeyL(22) = dw;
    dw = CamelliaSubkeyL(23) ^ CamelliaSubkeyR(23), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(23) = CamelliaSubkeyL(23) ^ dw, CamelliaSubkeyL(23) = dw;

    return;
}

static void camellia_setup256(const unsigned char *key, uint32_t *subkey)
{
    uint32_t kll,klr,krl,krr;           /* left half of key */
    uint32_t krll,krlr,krrl,krrr;       /* right half of key */
    uint32_t il, ir, t0, t1, w0, w1;    /* temporary variables */
    uint32_t kw4l, kw4r, dw, tl, tr;
    uint32_t subL[34];
    uint32_t subR[34];

    /**
     *  key = (kll || klr || krl || krr || krll || krlr || krrl || krrr)
     *  (|| is concatination)
     */

    kll  = GETU32(key     );
    klr  = GETU32(key +  4);
    krl  = GETU32(key +  8);
    krr  = GETU32(key + 12);
    krll = GETU32(key + 16);
    krlr = GETU32(key + 20);
    krrl = GETU32(key + 24);
    krrr = GETU32(key + 28);

    /* generate KL dependent subkeys */
    subl(0) = kll; subr(0) = klr;
    subl(1) = krl; subr(1) = krr;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 45);
    subl(12) = kll; subr(12) = klr;
    subl(13) = krl; subr(13) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(16) = kll; subr(16) = klr;
    subl(17) = krl; subr(17) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(22) = kll; subr(22) = klr;
    subl(23) = krl; subr(23) = krr;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 34);
    subl(30) = kll; subr(30) = klr;
    subl(31) = krl; subr(31) = krr;

    /* generate KR dependent subkeys */
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 15);
    subl(4) = krll; subr(4) = krlr;
    subl(5) = krrl; subr(5) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 15);
    subl(8) = krll; subr(8) = krlr;
    subl(9) = krrl; subr(9) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 30);
    subl(18) = krll; subr(18) = krlr;
    subl(19) = krrl; subr(19) = krrr;
    CAMELLIA_ROLDQo32(krll, krlr, krrl, krrr, w0, w1, 34);
    subl(26) = krll; subr(26) = krlr;
    subl(27) = krrl; subr(27) = krrr;
    CAMELLIA_ROLDQo32(krll, krlr, krrl, krrr, w0, w1, 34);

    /* generate KA */
    kll = subl(0) ^ krll; klr = subr(0) ^ krlr;
    krl = subl(1) ^ krrl; krr = subr(1) ^ krrr;
    CAMELLIA_F(kll, klr,
	       CAMELLIA_SIGMA1L, CAMELLIA_SIGMA1R,
	       w0, w1, il, ir, t0, t1);
    krl ^= w0; krr ^= w1;
    CAMELLIA_F(krl, krr,
	       CAMELLIA_SIGMA2L, CAMELLIA_SIGMA2R,
	       kll, klr, il, ir, t0, t1);
    kll ^= krll; klr ^= krlr;
    CAMELLIA_F(kll, klr,
	       CAMELLIA_SIGMA3L, CAMELLIA_SIGMA3R,
	       krl, krr, il, ir, t0, t1);
    krl ^= w0 ^ krrl; krr ^= w1 ^ krrr;
    CAMELLIA_F(krl, krr,
	       CAMELLIA_SIGMA4L, CAMELLIA_SIGMA4R,
	       w0, w1, il, ir, t0, t1);
    kll ^= w0; klr ^= w1;

    /* generate KB */
    krll ^= kll; krlr ^= klr;
    krrl ^= krl; krrr ^= krr;
    CAMELLIA_F(krll, krlr,
	       CAMELLIA_SIGMA5L, CAMELLIA_SIGMA5R,
	       w0, w1, il, ir, t0, t1);
    krrl ^= w0; krrr ^= w1;
    CAMELLIA_F(krrl, krrr,
	       CAMELLIA_SIGMA6L, CAMELLIA_SIGMA6R,
	       w0, w1, il, ir, t0, t1);
    krll ^= w0; krlr ^= w1;

    /* generate KA dependent subkeys */
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(6) = kll; subr(6) = klr;
    subl(7) = krl; subr(7) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 30);
    subl(14) = kll; subr(14) = klr;
    subl(15) = krl; subr(15) = krr;
    subl(24) = klr; subr(24) = krl;
    subl(25) = krr; subr(25) = kll;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 49);
    subl(28) = kll; subr(28) = klr;
    subl(29) = krl; subr(29) = krr;

    /* generate KB dependent subkeys */
    subl(2) = krll; subr(2) = krlr;
    subl(3) = krrl; subr(3) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 30);
    subl(10) = krll; subr(10) = krlr;
    subl(11) = krrl; subr(11) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 30);
    subl(20) = krll; subr(20) = krlr;
    subl(21) = krrl; subr(21) = krrr;
    CAMELLIA_ROLDQo32(krll, krlr, krrl, krrr, w0, w1, 51);
    subl(32) = krll; subr(32) = krlr;
    subl(33) = krrl; subr(33) = krrr;

    /* absorb kw2 to other subkeys */
    subl(3) ^= subl(1); subr(3) ^= subr(1);
    subl(5) ^= subl(1); subr(5) ^= subr(1);
    subl(7) ^= subl(1); subr(7) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(9);
    dw = subl(1) & subl(9), subr(1) ^= CAMELLIA_RL1(dw);
    subl(11) ^= subl(1); subr(11) ^= subr(1);
    subl(13) ^= subl(1); subr(13) ^= subr(1);
    subl(15) ^= subl(1); subr(15) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(17);
    dw = subl(1) & subl(17), subr(1) ^= CAMELLIA_RL1(dw);
    subl(19) ^= subl(1); subr(19) ^= subr(1);
    subl(21) ^= subl(1); subr(21) ^= subr(1);
    subl(23) ^= subl(1); subr(23) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(25);
    dw = subl(1) & subl(25), subr(1) ^= CAMELLIA_RL1(dw);
    subl(27) ^= subl(1); subr(27) ^= subr(1);
    subl(29) ^= subl(1); subr(29) ^= subr(1);
    subl(31) ^= subl(1); subr(31) ^= subr(1);
    subl(32) ^= subl(1); subr(32) ^= subr(1);

    /* absorb kw4 to other subkeys */
    kw4l = subl(33); kw4r = subr(33);
    subl(30) ^= kw4l; subr(30) ^= kw4r;
    subl(28) ^= kw4l; subr(28) ^= kw4r;
    subl(26) ^= kw4l; subr(26) ^= kw4r;
    kw4l ^= kw4r & ~subr(24);
    dw = kw4l & subl(24), kw4r ^= CAMELLIA_RL1(dw);
    subl(22) ^= kw4l; subr(22) ^= kw4r;
    subl(20) ^= kw4l; subr(20) ^= kw4r;
    subl(18) ^= kw4l; subr(18) ^= kw4r;
    kw4l ^= kw4r & ~subr(16);
    dw = kw4l & subl(16), kw4r ^= CAMELLIA_RL1(dw);
    subl(14) ^= kw4l; subr(14) ^= kw4r;
    subl(12) ^= kw4l; subr(12) ^= kw4r;
    subl(10) ^= kw4l; subr(10) ^= kw4r;
    kw4l ^= kw4r & ~subr(8);
    dw = kw4l & subl(8), kw4r ^= CAMELLIA_RL1(dw);
    subl(6) ^= kw4l; subr(6) ^= kw4r;
    subl(4) ^= kw4l; subr(4) ^= kw4r;
    subl(2) ^= kw4l; subr(2) ^= kw4r;
    subl(0) ^= kw4l; subr(0) ^= kw4r;

    /* key XOR is end of F-function */
    CamelliaSubkeyL(0) = subl(0) ^ subl(2);
    CamelliaSubkeyR(0) = subr(0) ^ subr(2);
    CamelliaSubkeyL(2) = subl(3);
    CamelliaSubkeyR(2) = subr(3);
    CamelliaSubkeyL(3) = subl(2) ^ subl(4);
    CamelliaSubkeyR(3) = subr(2) ^ subr(4);
    CamelliaSubkeyL(4) = subl(3) ^ subl(5);
    CamelliaSubkeyR(4) = subr(3) ^ subr(5);
    CamelliaSubkeyL(5) = subl(4) ^ subl(6);
    CamelliaSubkeyR(5) = subr(4) ^ subr(6);
    CamelliaSubkeyL(6) = subl(5) ^ subl(7);
    CamelliaSubkeyR(6) = subr(5) ^ subr(7);
    tl = subl(10) ^ (subr(10) & ~subr(8));
    dw = tl & subl(8), tr = subr(10) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(7) = subl(6) ^ tl;
    CamelliaSubkeyR(7) = subr(6) ^ tr;
    CamelliaSubkeyL(8) = subl(8);
    CamelliaSubkeyR(8) = subr(8);
    CamelliaSubkeyL(9) = subl(9);
    CamelliaSubkeyR(9) = subr(9);
    tl = subl(7) ^ (subr(7) & ~subr(9));
    dw = tl & subl(9), tr = subr(7) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(10) = tl ^ subl(11);
    CamelliaSubkeyR(10) = tr ^ subr(11);
    CamelliaSubkeyL(11) = subl(10) ^ subl(12);
    CamelliaSubkeyR(11) = subr(10) ^ subr(12);
    CamelliaSubkeyL(12) = subl(11) ^ subl(13);
    CamelliaSubkeyR(12) = subr(11) ^ subr(13);
    CamelliaSubkeyL(13) = subl(12) ^ subl(14);
    CamelliaSubkeyR(13) = subr(12) ^ subr(14);
    CamelliaSubkeyL(14) = subl(13) ^ subl(15);
    CamelliaSubkeyR(14) = subr(13) ^ subr(15);
    tl = subl(18) ^ (subr(18) & ~subr(16));
    dw = tl & subl(16), tr = subr(18) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(15) = subl(14) ^ tl;
    CamelliaSubkeyR(15) = subr(14) ^ tr;
    CamelliaSubkeyL(16) = subl(16);
    CamelliaSubkeyR(16) = subr(16);
    CamelliaSubkeyL(17) = subl(17);
    CamelliaSubkeyR(17) = subr(17);
    tl = subl(15) ^ (subr(15) & ~subr(17));
    dw = tl & subl(17), tr = subr(15) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(18) = tl ^ subl(19);
    CamelliaSubkeyR(18) = tr ^ subr(19);
    CamelliaSubkeyL(19) = subl(18) ^ subl(20);
    CamelliaSubkeyR(19) = subr(18) ^ subr(20);
    CamelliaSubkeyL(20) = subl(19) ^ subl(21);
    CamelliaSubkeyR(20) = subr(19) ^ subr(21);
    CamelliaSubkeyL(21) = subl(20) ^ subl(22);
    CamelliaSubkeyR(21) = subr(20) ^ subr(22);
    CamelliaSubkeyL(22) = subl(21) ^ subl(23);
    CamelliaSubkeyR(22) = subr(21) ^ subr(23);
    tl = subl(26) ^ (subr(26) & ~subr(24));
    dw = tl & subl(24), tr = subr(26) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(23) = subl(22) ^ tl;
    CamelliaSubkeyR(23) = subr(22) ^ tr;
    CamelliaSubkeyL(24) = subl(24);
    CamelliaSubkeyR(24) = subr(24);
    CamelliaSubkeyL(25) = subl(25);
    CamelliaSubkeyR(25) = subr(25);
    tl = subl(23) ^ (subr(23) &  ~subr(25));
    dw = tl & subl(25), tr = subr(23) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(26) = tl ^ subl(27);
    CamelliaSubkeyR(26) = tr ^ subr(27);
    CamelliaSubkeyL(27) = subl(26) ^ subl(28);
    CamelliaSubkeyR(27) = subr(26) ^ subr(28);
    CamelliaSubkeyL(28) = subl(27) ^ subl(29);
    CamelliaSubkeyR(28) = subr(27) ^ subr(29);
    CamelliaSubkeyL(29) = subl(28) ^ subl(30);
    CamelliaSubkeyR(29) = subr(28) ^ subr(30);
    CamelliaSubkeyL(30) = subl(29) ^ subl(31);
    CamelliaSubkeyR(30) = subr(29) ^ subr(31);
    CamelliaSubkeyL(31) = subl(30);
    CamelliaSubkeyR(31) = subr(30);
    CamelliaSubkeyL(32) = subl(32) ^ subl(31);
    CamelliaSubkeyR(32) = subr(32) ^ subr(31);

    /* apply the inverse of the last half of P-function */
    dw = CamelliaSubkeyL(2) ^ CamelliaSubkeyR(2), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(2) = CamelliaSubkeyL(2) ^ dw, CamelliaSubkeyL(2) = dw;
    dw = CamelliaSubkeyL(3) ^ CamelliaSubkeyR(3), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(3) = CamelliaSubkeyL(3) ^ dw, CamelliaSubkeyL(3) = dw;
    dw = CamelliaSubkeyL(4) ^ CamelliaSubkeyR(4), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(4) = CamelliaSubkeyL(4) ^ dw, CamelliaSubkeyL(4) = dw;
    dw = CamelliaSubkeyL(5) ^ CamelliaSubkeyR(5), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(5) = CamelliaSubkeyL(5) ^ dw, CamelliaSubkeyL(5) = dw;
    dw = CamelliaSubkeyL(6) ^ CamelliaSubkeyR(6), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(6) = CamelliaSubkeyL(6) ^ dw, CamelliaSubkeyL(6) = dw;
    dw = CamelliaSubkeyL(7) ^ CamelliaSubkeyR(7), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(7) = CamelliaSubkeyL(7) ^ dw, CamelliaSubkeyL(7) = dw;
    dw = CamelliaSubkeyL(10) ^ CamelliaSubkeyR(10), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(10) = CamelliaSubkeyL(10) ^ dw, CamelliaSubkeyL(10) = dw;
    dw = CamelliaSubkeyL(11) ^ CamelliaSubkeyR(11), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(11) = CamelliaSubkeyL(11) ^ dw, CamelliaSubkeyL(11) = dw;
    dw = CamelliaSubkeyL(12) ^ CamelliaSubkeyR(12), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(12) = CamelliaSubkeyL(12) ^ dw, CamelliaSubkeyL(12) = dw;
    dw = CamelliaSubkeyL(13) ^ CamelliaSubkeyR(13), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(13) = CamelliaSubkeyL(13) ^ dw, CamelliaSubkeyL(13) = dw;
    dw = CamelliaSubkeyL(14) ^ CamelliaSubkeyR(14), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(14) = CamelliaSubkeyL(14) ^ dw, CamelliaSubkeyL(14) = dw;
    dw = CamelliaSubkeyL(15) ^ CamelliaSubkeyR(15), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(15) = CamelliaSubkeyL(15) ^ dw, CamelliaSubkeyL(15) = dw;
    dw = CamelliaSubkeyL(18) ^ CamelliaSubkeyR(18), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(18) = CamelliaSubkeyL(18) ^ dw, CamelliaSubkeyL(18) = dw;
    dw = CamelliaSubkeyL(19) ^ CamelliaSubkeyR(19), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(19) = CamelliaSubkeyL(19) ^ dw, CamelliaSubkeyL(19) = dw;
    dw = CamelliaSubkeyL(20) ^ CamelliaSubkeyR(20), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(20) = CamelliaSubkeyL(20) ^ dw, CamelliaSubkeyL(20) = dw;
    dw = CamelliaSubkeyL(21) ^ CamelliaSubkeyR(21), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(21) = CamelliaSubkeyL(21) ^ dw, CamelliaSubkeyL(21) = dw;
    dw = CamelliaSubkeyL(22) ^ CamelliaSubkeyR(22), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(22) = CamelliaSubkeyL(22) ^ dw, CamelliaSubkeyL(22) = dw;
    dw = CamelliaSubkeyL(23) ^ CamelliaSubkeyR(23), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(23) = CamelliaSubkeyL(23) ^ dw, CamelliaSubkeyL(23) = dw;
    dw = CamelliaSubkeyL(26) ^ CamelliaSubkeyR(26), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(26) = CamelliaSubkeyL(26) ^ dw, CamelliaSubkeyL(26) = dw;
    dw = CamelliaSubkeyL(27) ^ CamelliaSubkeyR(27), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(27) = CamelliaSubkeyL(27) ^ dw, CamelliaSubkeyL(27) = dw;
    dw = CamelliaSubkeyL(28) ^ CamelliaSubkeyR(28), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(28) = CamelliaSubkeyL(28) ^ dw, CamelliaSubkeyL(28) = dw;
    dw = CamelliaSubkeyL(29) ^ CamelliaSubkeyR(29), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(29) = CamelliaSubkeyL(29) ^ dw, CamelliaSubkeyL(29) = dw;
    dw = CamelliaSubkeyL(30) ^ CamelliaSubkeyR(30), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(30) = CamelliaSubkeyL(30) ^ dw, CamelliaSubkeyL(30) = dw;
    dw = CamelliaSubkeyL(31) ^ CamelliaSubkeyR(31), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(31) = CamelliaSubkeyL(31) ^ dw, CamelliaSubkeyL(31) = dw;
    
    return;
}

static void camellia_setup192(const unsigned char *key, uint32_t *subkey)
{
    unsigned char kk[32];
    uint32_t krll, krlr, krrl,krrr;

    memcpy(kk, key, 24);
    memcpy((unsigned char *)&krll, key+16,4);
    memcpy((unsigned char *)&krlr, key+20,4);
    krrl = ~krll;
    krrr = ~krlr;
    memcpy(kk+24, (unsigned char *)&krrl, 4);
    memcpy(kk+28, (unsigned char *)&krrr, 4);
    camellia_setup256(kk, subkey);
    return;
}


/**
 * Stuff related to camellia encryption/decryption
 *
 * "io" must be 4byte aligned and big-endian data.
 */
static void camellia_encrypt128(const uint32_t *subkey, uint32_t *io)
{
    uint32_t il, ir, t0, t1;

    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(0);
    io[1] ^= CamelliaSubkeyR(0);
    /* main iteration */

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(2),CamelliaSubkeyR(2),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(3),CamelliaSubkeyR(3),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(4),CamelliaSubkeyR(4),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(5),CamelliaSubkeyR(5),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(6),CamelliaSubkeyR(6),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(7),CamelliaSubkeyR(7),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(8),CamelliaSubkeyR(8),
		 CamelliaSubkeyL(9),CamelliaSubkeyR(9),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(10),CamelliaSubkeyR(10),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(11),CamelliaSubkeyR(11),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(12),CamelliaSubkeyR(12),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(13),CamelliaSubkeyR(13),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(14),CamelliaSubkeyR(14),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(15),CamelliaSubkeyR(15),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(16),CamelliaSubkeyR(16),
		 CamelliaSubkeyL(17),CamelliaSubkeyR(17),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(18),CamelliaSubkeyR(18),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(19),CamelliaSubkeyR(19),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(20),CamelliaSubkeyR(20),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(21),CamelliaSubkeyR(21),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(22),CamelliaSubkeyR(22),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(23),CamelliaSubkeyR(23),
		     io[0],io[1],il,ir,t0,t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(24);
    io[3] ^= CamelliaSubkeyR(24);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;
	
    return;
}

static void camellia_decrypt128(const uint32_t *subkey, uint32_t *io)
{
    uint32_t il,ir,t0,t1;               /* temporary valiables */
    
    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(24);
    io[1] ^= CamelliaSubkeyR(24);

    /* main iteration */
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(23),CamelliaSubkeyR(23),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(22),CamelliaSubkeyR(22),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(21),CamelliaSubkeyR(21),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(20),CamelliaSubkeyR(20),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(19),CamelliaSubkeyR(19),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(18),CamelliaSubkeyR(18),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(17),CamelliaSubkeyR(17),
		 CamelliaSubkeyL(16),CamelliaSubkeyR(16),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(15),CamelliaSubkeyR(15),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(14),CamelliaSubkeyR(14),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(13),CamelliaSubkeyR(13),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(12),CamelliaSubkeyR(12),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(11),CamelliaSubkeyR(11),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(10),CamelliaSubkeyR(10),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(9),CamelliaSubkeyR(9),
		 CamelliaSubkeyL(8),CamelliaSubkeyR(8),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(7),CamelliaSubkeyR(7),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(6),CamelliaSubkeyR(6),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(5),CamelliaSubkeyR(5),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(4),CamelliaSubkeyR(4),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(3),CamelliaSubkeyR(3),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(2),CamelliaSubkeyR(2),
		     io[0],io[1],il,ir,t0,t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(0);
    io[3] ^= CamelliaSubkeyR(0);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;

    return;
}

/**
 * stuff for 192 and 256bit encryption/decryption
 */
static void camellia_encrypt256(const uint32_t *subkey, uint32_t *io)
{
    uint32_t il,ir,t0,t1;           /* temporary valiables */

    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(0);
    io[1] ^= CamelliaSubkeyR(0);

    /* main iteration */
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(2),CamelliaSubkeyR(2),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(3),CamelliaSubkeyR(3),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(4),CamelliaSubkeyR(4),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(5),CamelliaSubkeyR(5),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(6),CamelliaSubkeyR(6),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(7),CamelliaSubkeyR(7),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(8),CamelliaSubkeyR(8),
		 CamelliaSubkeyL(9),CamelliaSubkeyR(9),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(10),CamelliaSubkeyR(10),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(11),CamelliaSubkeyR(11),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(12),CamelliaSubkeyR(12),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(13),CamelliaSubkeyR(13),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(14),CamelliaSubkeyR(14),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(15),CamelliaSubkeyR(15),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(16),CamelliaSubkeyR(16),
		 CamelliaSubkeyL(17),CamelliaSubkeyR(17),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(18),CamelliaSubkeyR(18),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(19),CamelliaSubkeyR(19),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(20),CamelliaSubkeyR(20),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(21),CamelliaSubkeyR(21),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(22),CamelliaSubkeyR(22),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(23),CamelliaSubkeyR(23),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(24),CamelliaSubkeyR(24),
		 CamelliaSubkeyL(25),CamelliaSubkeyR(25),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(26),CamelliaSubkeyR(26),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(27),CamelliaSubkeyR(27),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(28),CamelliaSubkeyR(28),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(29),CamelliaSubkeyR(29),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(30),CamelliaSubkeyR(30),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(31),CamelliaSubkeyR(31),
		     io[0],io[1],il,ir,t0,t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(32);
    io[3] ^= CamelliaSubkeyR(32);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;

    return;
}

static void camellia_decrypt256(const uint32_t *subkey, uint32_t *io)
{
    uint32_t il,ir,t0,t1;           /* temporary valiables */

    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(32);
    io[1] ^= CamelliaSubkeyR(32);
	
    /* main iteration */
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(31),CamelliaSubkeyR(31),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(30),CamelliaSubkeyR(30),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(29),CamelliaSubkeyR(29),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(28),CamelliaSubkeyR(28),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(27),CamelliaSubkeyR(27),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(26),CamelliaSubkeyR(26),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(25),CamelliaSubkeyR(25),
		 CamelliaSubkeyL(24),CamelliaSubkeyR(24),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(23),CamelliaSubkeyR(23),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(22),CamelliaSubkeyR(22),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(21),CamelliaSubkeyR(21),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(20),CamelliaSubkeyR(20),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(19),CamelliaSubkeyR(19),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(18),CamelliaSubkeyR(18),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(17),CamelliaSubkeyR(17),
		 CamelliaSubkeyL(16),CamelliaSubkeyR(16),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(15),CamelliaSubkeyR(15),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(14),CamelliaSubkeyR(14),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(13),CamelliaSubkeyR(13),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(12),CamelliaSubkeyR(12),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(11),CamelliaSubkeyR(11),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(10),CamelliaSubkeyR(10),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(9),CamelliaSubkeyR(9),
		 CamelliaSubkeyL(8),CamelliaSubkeyR(8),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(7),CamelliaSubkeyR(7),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(6),CamelliaSubkeyR(6),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(5),CamelliaSubkeyR(5),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(4),CamelliaSubkeyR(4),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(3),CamelliaSubkeyR(3),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(2),CamelliaSubkeyR(2),
		     io[0],io[1],il,ir,t0,t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(0);
    io[3] ^= CamelliaSubkeyR(0);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;

    return;
}

/***
 *
 * API for compatibility
 */

void Camellia_Ekeygen(int keyBitLength,
		      const unsigned char *rawKey, 
		      KeyTableType *keyTable)
{
    assert(keyBitLength==128 || keyBitLength==192 || keyBitLength==256);
    switch(keyBitLength) {
    case 128:
	camellia_setup128(rawKey, keyTable);
	break;
    case 192:
	camellia_setup192(rawKey, keyTable);
	break;
    case 256:
	camellia_setup256(rawKey, keyTable);
	break;
    default:
	break;
    }
}


void Camellia_EncryptBlock(int keyBitLength,
			   const unsigned char *plaintext, 
			   const KeyTableType *keyTable,
			   unsigned char *ciphertext)
{
    uint32_t tmp[4];

    assert(keyBitLength==128 || keyBitLength==192 || keyBitLength==256);

    tmp[0] = GETU32(plaintext);
    tmp[1] = GETU32(plaintext + 4);
    tmp[2] = GETU32(plaintext + 8);
    tmp[3] = GETU32(plaintext + 12);

    switch (keyBitLength) {
    case 128:
	camellia_encrypt128(keyTable, tmp);
	break;
    case 192:
	/* fall through */
    case 256:
	camellia_encrypt256(keyTable, tmp);
	break;
    default:
	break;
    }

    PUTU32(ciphertext, tmp[0]);
    PUTU32(ciphertext + 4, tmp[1]);
    PUTU32(ciphertext + 8, tmp[2]);
    PUTU32(ciphertext + 12, tmp[3]);
}

void Camellia_DecryptBlock(int keyBitLength,
			   const unsigned char *ciphertext, 
			   const KeyTableType *keyTable,
			   unsigned char *plaintext)
{
    uint32_t tmp[4];

    assert(keyBitLength==128 || keyBitLength==192 || keyBitLength==256);

    tmp[0] = GETU32(ciphertext);
    tmp[1] = GETU32(ciphertext + 4);
    tmp[2] = GETU32(ciphertext + 8);
    tmp[3] = GETU32(ciphertext + 12);

    switch (keyBitLength) {
    case 128:
	camellia_decrypt128(keyTable, tmp);
	break;
    case 192:
	/* fall through */
    case 256:
	camellia_decrypt256(keyTable, tmp);
	break;
    default:
	break;
    }
    PUTU32(plaintext, tmp[0]);
    PUTU32(plaintext + 4, tmp[1]);
    PUTU32(plaintext + 8, tmp[2]);
    PUTU32(plaintext + 12, tmp[3]);
}
