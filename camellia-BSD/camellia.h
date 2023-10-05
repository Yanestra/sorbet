/* camellia.h ver 1.2.0
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

#ifndef HEADER_CAMELLIA_H
#define HEADER_CAMELLIA_H

//#ifdef  __cplusplus
//extern "C" {
//#endif

#define CAMELLIA_BLOCK_SIZE 16
#define CAMELLIA_TABLE_BYTE_LEN 272
#define CAMELLIA_TABLE_WORD_LEN (CAMELLIA_TABLE_BYTE_LEN / 4)

//typedef uint32_t KEY_TABLE_TYPE[CAMELLIA_TABLE_WORD_LEN];
typedef uint32_t KeyTableType;


void Camellia_Ekeygen(int keyBitLength,
		      const uint8_t *rawKey,
		      KeyTableType *keyTable);

void Camellia_EncryptBlock(int keyBitLength,
			   const uint8_t *plaintext,
			   const KeyTableType *keyTable,
			   uint8_t *cipherText);

void Camellia_DecryptBlock(int keyBitLength,
			   const uint8_t *cipherText,
			   const KeyTableType *keyTable,
			   uint8_t *plaintext);



/* this is the old implementation API (kjw) */

#define CAMELLIA_KEYSIZE CAMELLIA_TABLE_BYTE_LEN
#define CAMELLIA_BUFSIZE CAMELLIA_BLOCK_SIZE

#define camellia_ekeygen(rawk, keyt) Camellia_Ekeygen(256, rawk, keyt)
#define camellia_encrypt(p,k,c) Camellia_EncryptBlock(256, p, k, c)
#define camellia_decrypt(c,k,p) Camellia_DecryptBlock(256, c, k, p)


//#ifdef  __cplusplus
//}
//#endif

#endif /* HEADER_CAMELLIA_H */
