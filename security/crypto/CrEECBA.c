/* crypto/evp/e_cbc_d.c */

/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)

 * All rights reserved.

 *

 * This package is an SSL implementation written

 * by Eric Young (eay@cryptsoft.com).

 * The implementation was written so as to conform with Netscapes SSL.

 * 

 * This library is free for commercial and non-commercial use as CrLONG32 as

 * the following conditions are aheared to.  The following conditions

 * apply to all code found in this distribution, be it the RC4, RSA,

 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation

 * included with this distribution is covered by the same copyright terms

 * except that the holder is Tim Hudson (tjh@cryptsoft.com).

 * 

 * Copyright remains Eric Young's, and as such any Copyright notices in

 * the code are not to be removed.

 * If this package is used in a product, Eric Young should be given attribution

 * as the author of the parts of the library used.

 * This can be in the form of a textual message at program startup or

 * in documentation (online or textual) provided with the package.

 * 

 * Redistribution and use in source and binary forms, with or without

 * modification, are permitted provided that the following conditions

 * are met:

 * 1. Redistributions of source code must retain the copyright

 *    notice, this list of conditions and the following disclaimer.

 * 2. Redistributions in binary form must reproduce the above copyright

 *    notice, this list of conditions and the following disclaimer in the

 *    documentation and/or other materials provided with the distribution.

 * 3. All advertising materials mentioning features or use of this software

 *    must display the following acknowledgement:

 *    "This product includes cryptographic software written by

 *     Eric Young (eay@cryptsoft.com)"

 *    The word 'cryptographic' can be left out if the rouines from the library

 *    being used are not cryptographic related :-).

 * 4. If you include any Windows specific code (or a derivative thereof) from 

 *    the apps directory (application code) you must include an acknowledgement:

 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"

 * 

 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND

 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE

 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE

 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE

 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL

 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS

 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)

 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT

 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY

 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF

 * SUCH DAMAGE.

 * 

 * The licence and distribution terms for any publically available version or

 * derivative of this code cannot be changed.  i.e. this code cannot simply be

 * copied and put under another distribution licence

 * [including the GNU Public Licence.]

 */



#include "crypto/CrConfig.h"

#ifdef CR_AES





#include "crypto/CrSMemMgr.h"

#include "crypto/CrEvp.h"





/**

 *	2001.06.25 Removed by Taesung Kim. (OBJECT_ID_REMOVE)

 *	Object-ID is not needed in crypto module

 */

//#include "Objects.h"



#ifndef NOPROTO

static void aes_ecb_init_key_128(EVP_CIPHER_CTX *ctx, CrUINT8 *key,

	CrUINT8 *iv,CrINT32 enc);

static void aes_ecb_cipher_128(EVP_CIPHER_CTX *ctx, CrUINT8 *out,

	CrUINT8 *in, CrUINT32 inl);

static void aes_ecb_init_key_192(EVP_CIPHER_CTX *ctx, CrUINT8 *key,

	CrUINT8 *iv,CrINT32 enc);

static void aes_ecb_cipher_192(EVP_CIPHER_CTX *ctx, CrUINT8 *out,

	CrUINT8 *in, CrUINT32 inl);

static void aes_ecb_init_key_256(EVP_CIPHER_CTX *ctx, CrUINT8 *key,

	CrUINT8 *iv,CrINT32 enc);

static void aes_ecb_cipher_256(EVP_CIPHER_CTX *ctx, CrUINT8 *out,

	CrUINT8 *in, CrUINT32 inl);

#else

static void aes_ecb_init_key_128();

static void aes_ecb_cipher_128();

static void aes_ecb_init_key_192();

static void aes_ecb_cipher_192();

static void aes_ecb_init_key_256();

static void aes_ecb_cipher_256();

#endif



/*                   AES ECB Mode 128 bits                */



static EVP_CIPHER a_ecb_cipher_128 =

{

//	NID_aes_ecb,

	16,

	16,

	16,

	aes_ecb_init_key_128,

	aes_ecb_cipher_128,

	NULL,

	sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+

		sizeof((((EVP_CIPHER_CTX *)NULL)->c.aes)),

//	EVP_CIPHER_get_asn1_iv,

//	EVP_CIPHER_set_asn1_iv,

	NULL,

	NULL,

};



EVP_CIPHER *EVP_aes_ecb_128()

{

	return(&a_ecb_cipher_128);

}

	

static void aes_ecb_init_key_128(EVP_CIPHER_CTX *ctx, CrUINT8 *key, CrUINT8 *iv,CrINT32 enc)

{

	ctx->cipher->block_size = 16;



	makeKey(&(ctx->c.aes.ki), enc, 128, key);

	cipherInit(&(ctx->c.aes.ci), MODE_ECB, iv);



	if (iv != NULL)

		SMemcpy(&(ctx->c.aes.ci.IV[0]),iv,16);

}



static void aes_ecb_cipher_128(EVP_CIPHER_CTX *ctx, CrUINT8 *out, CrUINT8 *in, CrUINT32 inl)

{

	if (ctx->encrypt) 

		AESEncrypt(&(ctx->c.aes.ci), &(ctx->c.aes.ki), in, inl*8, out);

	else 

		AESDecrypt(&(ctx->c.aes.ci), &(ctx->c.aes.ki), in, inl*8, out);

}



/*                   AES ECB Mode 192 bits                */



static EVP_CIPHER a_ecb_cipher_192 =

{

//	NID_aes_ecb,

	16,

	24,

	16,

	aes_ecb_init_key_192,

	aes_ecb_cipher_192,

	NULL,

	sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+

		sizeof((((EVP_CIPHER_CTX *)NULL)->c.aes)),

//	EVP_CIPHER_get_asn1_iv,

//	EVP_CIPHER_set_asn1_iv,

	NULL,

	NULL,

};



EVP_CIPHER *EVP_aes_ecb_192 ()

{

	return(&a_ecb_cipher_192);

}

	

static void aes_ecb_init_key_192(EVP_CIPHER_CTX *ctx, CrUINT8 *key, CrUINT8 *iv,CrINT32 enc)

{

	ctx->cipher->block_size = 16;



	makeKey(&(ctx->c.aes.ki), enc, 192, key);

	cipherInit(&(ctx->c.aes.ci), MODE_ECB, iv);



	if (iv != NULL)

		SMemcpy(&(ctx->c.aes.ci.IV[0]),iv,16);

}



static void aes_ecb_cipher_192(EVP_CIPHER_CTX *ctx, CrUINT8 *out, CrUINT8 *in, CrUINT32 inl)

{

	if (ctx->encrypt) 

		AESEncrypt(&(ctx->c.aes.ci), &(ctx->c.aes.ki), in, inl*8, out);

	else 

		AESDecrypt(&(ctx->c.aes.ci), &(ctx->c.aes.ki), in, inl*8, out);

}



/*                   AES ECB Mode 256 bits                */



static EVP_CIPHER a_ecb_cipher_256 =

{

//	NID_aes_ecb,

	16,

	32,

	16,

	aes_ecb_init_key_256,

	aes_ecb_cipher_256,

	NULL,

	sizeof(EVP_CIPHER_CTX)-sizeof((((EVP_CIPHER_CTX *)NULL)->c))+

		sizeof((((EVP_CIPHER_CTX *)NULL)->c.aes)),

//	EVP_CIPHER_get_asn1_iv,

//	EVP_CIPHER_set_asn1_iv,

	NULL,

	NULL,

};



EVP_CIPHER *EVP_aes_ecb_256()

{

	return(&a_ecb_cipher_256);

}

	

static void aes_ecb_init_key_256(EVP_CIPHER_CTX *ctx, CrUINT8 *key, CrUINT8 *iv,CrINT32 enc)

{

	ctx->cipher->block_size = 16;



	makeKey(&(ctx->c.aes.ki), enc, 256, key);

	cipherInit(&(ctx->c.aes.ci), MODE_ECB, iv);



	if (iv != NULL)

		SMemcpy(&(ctx->c.aes.ci.IV[0]),iv,16);

}



static void aes_ecb_cipher_256(EVP_CIPHER_CTX *ctx, CrUINT8 *out, CrUINT8 *in, CrUINT32 inl)

{

	if (ctx->encrypt) 

		AESEncrypt(&(ctx->c.aes.ci), &(ctx->c.aes.ki), in, inl*8, out);

	else 

		AESDecrypt(&(ctx->c.aes.ci), &(ctx->c.aes.ki), in, inl*8, out);

}



#endif // #ifdef CR_AES


