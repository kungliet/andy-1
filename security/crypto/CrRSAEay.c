 /* crypto/rsa/rsa_eay.c */
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
#ifdef CR_RSA
//#include "crypto/cryptlib.h"

#include "crypto/CrSMemMgr.h"
#include "crypto/CrBN.h"
#include "crypto/CrRSA.h"
//#include "crypto/DebugPrint.h"

#ifdef SWC_RANDOM_NUMBER  /*Defined in "cryptlib.h"*/
#	include "crypto/CrSwcRand.h"
#	define RAND_bytes(a, b) getRandomBytes(a, b)
#else
#	include "crypto/CrRand.h"
#endif

#ifndef NOPROTO

static CrINT32 RSA_eay_public_encrypt(CrINT32 flen, CrUINT8 *from, CrUINT8 *to, RSA *rsa,CrINT32 padding);
static CrINT32 RSA_eay_private_encrypt(CrINT32 flen, CrUINT8 *from,	CrUINT8 *to, RSA *rsa,CrINT32 padding);
static CrINT32 RSA_eay_public_decrypt(CrINT32 flen, CrUINT8 *from, CrUINT8 *to, RSA *rsa,CrINT32 padding);
static CrINT32 RSA_eay_private_decrypt(CrINT32 flen, CrUINT8 *from,	CrUINT8 *to, RSA *rsa,CrINT32 padding);
static CrINT32 RSA_eay_mod_exp(BIGNUM *r0, BIGNUM *i, RSA *rsa);
//static CrINT32 RSA_eay_init(RSA *rsa);
//static CrINT32 RSA_eay_finish(RSA *rsa);

#else // #ifndef NOPROTO

static CrINT32 RSA_eay_public_encrypt();
static CrINT32 RSA_eay_private_encrypt();
static CrINT32 RSA_eay_public_decrypt();
static CrINT32 RSA_eay_private_decrypt();
static CrINT32 RSA_eay_mod_exp();
//static CrINT32 RSA_eay_init();
//static CrINT32 RSA_eay_finish();

#endif // #ifndef NOPROTO


 /**
 *Taesung Kim Modified (2001/1/31)
 *Original Code
 *	RSA_private_decrypt
 *	RSA_eay_init,
 *	RSA_eay_finish,
 *There is no need to running init and finish rootines
 *
 *Modified Code
 *	NULL,
 *	NULL,
 *	NULL,
 */
static RSA_METHOD rsa_pkcs1_eay_meth=
{
	NULL, //"Eric Young's PKCS#1 RSA",
	RSA_eay_public_encrypt,
	RSA_eay_public_decrypt,
	RSA_eay_private_encrypt,
	RSA_eay_private_decrypt, // if private decryption operation is not needed, then use 'NULL'
	RSA_eay_mod_exp,
	BN_mod_exp_mont,
	NULL, /*RSA_eay_init*/
	NULL, /*RSA_eay_finish*/
	0,
	NULL,
};

RSA_METHOD*
RSA_PKCS1_SSLeay()
{
	return(&rsa_pkcs1_eay_meth);
}

 /**
 *	RSA_eay_public_encrypt
 *	Return Value
 *	SUCCESS : modulus size (bytes), FAIL : -1 or 0
 */

static CrINT32
RSA_eay_public_encrypt(
	CrINT32		flen,
	CrUINT8*	from,
	CrUINT8*	to,
	RSA*		rsa,
	CrINT32 	padding)
{
	BIGNUM *f=NULL,*ret=NULL;
	CrINT32 i,j,k,num=0,r= -1;
	CrUINT8 *p; /*Taesung Kim Added (2001.02.06) for temp pointer of buf*/
	CrUINT8 *buf=NULL;
	BN_CTX *ctx=NULL;

	if ((ctx=BN_CTX_new()) == NULL)
		goto err;
	num=BN_num_bytes(rsa->n);
	if ((buf=(CrUINT8 *)SMalloc(num)) == NULL)
	{
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_EAY_PUBLIC_ENCRYPT,ERR_R_MALLOC_FAILURE);
#endif
		goto err;
	}

	 /**
	 *	Taesung Kim Modified (2001.02.06)
	 *	
	 *	The padding function is merged to this source file.
	 *	The origin function was located in rsa_pk1.c file.
	 *	Merged in order to reduce the size of library.
	 */
	if (flen > (num-11))
	{
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2,RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
#endif
		return(0);
	}
	
	p = (CrUINT8 *)buf;
	*(p++) = 0;
	*(p++) = 2;  /*Public Key BT(Block Type)*/
	
	 /*pad out with non-zero random data*/
	j = num-3-flen;
	RAND_bytes(p,j);
	for (i = 0; i < j; i++)
	{
		if (*p == '\0')
			do {
				RAND_bytes(p,1);
			} while (*p == '\0');
		p++;
	}

	*(p++) = '\0';
	SMemcpy(p,from,(CrUINT32)flen);

	if (((f=BN_new()) == NULL) || ((ret=BN_new()) == NULL))
		goto err;
	if (BN_bin2bn(buf,num,f) == NULL)
		goto err;
	if ((rsa->method_mod_n == NULL) && (rsa->flags & RSA_FLAG_CACHE_PUBLIC))
	{
		if ((rsa->method_mod_n=(CrINT8 *)BN_MONT_CTX_new()) != NULL)
		{
			if (!BN_MONT_CTX_set((BN_MONT_CTX *)rsa->method_mod_n,rsa->n,ctx))
				goto err;
		}
	}
	if (!rsa->meth->bn_mod_exp(ret,f,rsa->e,rsa->n,ctx,(BN_MONT_CTX *)rsa->method_mod_n)) 
		goto err;

	 /* put in leading 0 bytes if the number is less than the
	 * length of the modulus */
	j=BN_num_bytes(ret);
	i=BN_bn2bin(ret,&(to[num-j]));
	for (k=0; k<(num-i); k++)
		to[k]=0;

	r=num;

err:
	if (ctx != NULL)
		BN_CTX_free(ctx);
	if (f != NULL)
		BN_free(f);
	if (ret != NULL)
		BN_free(ret);
	if (buf != NULL) 
	{
		SMemset(buf,0,num);
		SFree(buf);
	}

	return(r);
}

 /**
 *	RSA_eay_private_encrypt
 *	RETURN VALUE
 *		SUCCESS	: modulus size (bytes)
 *		FAILURE	: -1 or 0
 */

static CrINT32
RSA_eay_private_encrypt(
	CrINT32		flen,
	CrUINT8*	from,
	CrUINT8*	to,
	RSA*		rsa,
	CrINT32 	padding)
{
	BIGNUM *f=NULL,*ret=NULL;
	CrINT32 i,j,k,num=0,r= -1;
	CrUINT8 *p;  /*temp pointer of buf*/
	CrUINT8 *buf=NULL;
	BN_CTX *ctx=NULL;

	if ((ctx=BN_CTX_new()) == NULL) 
		goto err;
	num=BN_num_bytes(rsa->n);
	if ((buf=(CrUINT8 *)SMalloc(num)) == NULL)
	{
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,ERR_R_MALLOC_FAILURE);
#endif
		goto err;
	}

	 /**
	 *	Taesung Kim Modified (2001.02.06)
	 *	
	 *	The padding function is merged to this source file.
	 *	The origin function was located in rsa_pk1.c file.
	 *	Merged in order to reduce the size of library.
	 */
	if (flen > (num-11))
	{
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1,RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
#endif
		return(0);
	}
	
	p = (CrUINT8 *)buf;
	
	*(p++)=0;
	*(p++)=1;  /* Private Key BT (Block Type) */

	 /* padd out with 0xff data */
	j=num-3-flen;
	SMemset(p,0xff,j);
	p+=j;
	*(p++)='\0';
	SMemcpy(p, from, (CrUINT32)flen);	

	if (((f=BN_new()) == NULL) || ((ret=BN_new()) == NULL)) 
		goto err;
	if (BN_bin2bn(buf,num,f) == NULL) 
		goto err;

	if ((rsa->flags & RSA_FLAG_BLINDING) && (rsa->blinding == NULL))
		RSA_blinding_on(rsa,ctx);
	if (rsa->flags & RSA_FLAG_BLINDING)
		if (!BN_BLINDING_convert(f,rsa->blinding,ctx)) 
			goto err;

	if ((rsa->p != NULL) &&
		(rsa->q != NULL) &&
		(rsa->dmp1 != NULL) &&
		(rsa->dmq1 != NULL) &&
		(rsa->iqmp != NULL))
	{
			if (!rsa->meth->rsa_mod_exp(ret,f,rsa)) 
				goto err;
	}
	else
	{
		if (!rsa->meth->bn_mod_exp(ret,f,rsa->d,rsa->n,ctx,NULL)) 
			goto err;
	}

	if (rsa->flags & RSA_FLAG_BLINDING)
	{
		if (!BN_BLINDING_invert(ret,rsa->blinding,ctx)) 
			goto err;
	}
	 /* put in leading 0 bytes if the number is less than the
	 * length of the modulus */
	j=BN_num_bytes(ret);
	i=BN_bn2bin(ret,&(to[num-j]));
	for (k=0; k<(num-i); k++)
		to[k]=0;

	r=num;

err:
	if (ctx != NULL)
		BN_CTX_free(ctx);
	if (ret != NULL)
		BN_free(ret);
	if (f != NULL)
		BN_free(f);
	if (buf != NULL)
	{
		SMemset(buf,0,num);
		SFree(buf);
	}

	return(r);
}


static CrINT32 RSA_eay_private_decrypt(
	CrINT32		flen,
	CrUINT8		*from,
	CrUINT8		*to,
	RSA			*rsa,
	CrINT32		padding
)
{
	BIGNUM *f=NULL,*ret=NULL;
	CrINT32 j,num=0,r= -1;
	CrUINT8 *p;
	CrUINT8 *buf=NULL;
	BN_CTX *ctx=NULL;

	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;

	num=BN_num_bytes(rsa->n);

	if ((buf=(CrUINT8 *)SMalloc(num)) == NULL)
		{
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,ERR_R_MALLOC_FAILURE);
#endif
		goto err;
		}

	 /* This check was for equallity but PGP does evil things
	 * and chops off the top '0' bytes */
	if (flen > num)
		{
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,RSA_R_DATA_GREATER_THAN_MOD_LEN);
#endif
		goto err;
		}

	 /* make data into a big number */
	if (((ret=BN_new()) == NULL) || ((f=BN_new()) == NULL)) goto err;
	if (BN_bin2bn(from,(CrINT32)flen,f) == NULL) goto err;

	if ((rsa->flags & RSA_FLAG_BLINDING) && (rsa->blinding == NULL))
		RSA_blinding_on(rsa,ctx);
	if (rsa->flags & RSA_FLAG_BLINDING)
		if (!BN_BLINDING_convert(f,rsa->blinding,ctx)) goto err;

	 /* do the decrypt */
	if ((rsa->p != NULL) &&
		(rsa->q != NULL) &&
		(rsa->dmp1 != NULL) &&
		(rsa->dmq1 != NULL) &&
		(rsa->iqmp != NULL))
		{ if (!rsa->meth->rsa_mod_exp(ret,f,rsa)) goto err; }
	else
		{
		if (!rsa->meth->bn_mod_exp(ret,f,rsa->d,rsa->n,ctx,NULL))
			goto err;
		}

	if (rsa->flags & RSA_FLAG_BLINDING)
		if (!BN_BLINDING_invert(ret,rsa->blinding,ctx)) goto err;

	p=buf;
	j=BN_bn2bin(ret,p);  /* j is only used with no-padding mode */

	switch (padding)
		{
	case RSA_PKCS1_PADDING:
		r=RSA_padding_check_PKCS1_type_2(to,num,buf,j);
		break;
#if 0
	case RSA_SSLV23_PADDING:
		r=RSA_padding_check_SSLv23(to,num,buf,j);
		break;
	case RSA_NO_PADDING:
		r=RSA_padding_check_none(to,num,buf,j);
		break;
#endif // end of #if 0
	default:
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,RSA_R_UNKNOWN_PADDING_TYPE);
#endif
		goto err;
		}
	if (r < 0)
	{
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,RSA_R_PADDING_CHECK_FAILED);
#endif
	}

err:
	if (ctx != NULL) BN_CTX_free(ctx);
	if (f != NULL) BN_free(f);
	if (ret != NULL) BN_free(ret);
	if (buf != NULL)
	{
		SMemset(buf,0,num);
		SFree(buf);
	}
	return(r);
}



CrINT32
RSA_padding_check_PKCS1_type_2(
	CrUINT8* 	to,
	CrINT32		tlen,
	CrUINT8*	from,
	CrINT32		flen
)
{
	CrINT32 i,j;
	CrUINT8 *p;

	p=from;
	if (*(p++) != 02)
	{
		return(-1);
	}

	/* scan over padding data */
	j=flen-1; /* one for type. */
	for (i=0; i<j; i++)
		if (*(p++) == 0) break;

	if (i == j)
	{
		return(-1);
	}

	if (i < 8)
	{
		return(-1);
	}

	i++; /* Skip over the '\0' */
	j-=i;
	SMemcpy(to,p,(CrUINT32)j);

	return(j);
}



 /**
 *	RSA_eay_public_decrypt
 *	RETURN VALUE
 *		SUCCESS	: size of result of the hash function
 *				  EX.) TLS : SHA1(Data) = 20 (bytes)
 *		FAILURE	: -1
 */
static
CrINT32 RSA_eay_public_decrypt(
	CrINT32		flen,
	CrUINT8*	from,
	CrUINT8*	to,
	RSA*		rsa,
	CrINT32 	padding)
{
	BIGNUM *f=NULL,*ret=NULL;
	CrINT32 i,num=0,r= -1;
	CrUINT8 *p;
	CrUINT8 *buf=NULL;
	BN_CTX *ctx=NULL;

	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;

	num=BN_num_bytes(rsa->n);
	buf=(CrUINT8 *)SMalloc(num);
	if (buf == NULL)
	{
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT,ERR_R_MALLOC_FAILURE);
#endif
		goto err;
	}

	 /* This check was for equallity but PGP does evil things
	 * and chops off the top '0' bytes */
	if (flen > num)
	{
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT,RSA_R_DATA_GREATER_THAN_MOD_LEN);
#endif
		goto err;
	}

	 /* make data into a big number */
	if (((ret=BN_new()) == NULL) || ((f=BN_new()) == NULL)) 
		goto err;

	if (BN_bin2bn(from,flen,f) == NULL) 
		goto err;

	 /* do the decrypt */
	if ((rsa->method_mod_n == NULL) && (rsa->flags & RSA_FLAG_CACHE_PUBLIC))
	{
		if ((rsa->method_mod_n=(CrINT8 *)BN_MONT_CTX_new()) != NULL)
		{
			if (!BN_MONT_CTX_set((BN_MONT_CTX *)rsa->method_mod_n,rsa->n,ctx)) 
				goto err;
		}
	}

	if (!rsa->meth->bn_mod_exp(ret,f,rsa->e,rsa->n,ctx,(BN_MONT_CTX *)rsa->method_mod_n))
		goto err;

	p=buf;
	i=BN_bn2bin(ret,p);

	if (*(p++) != 01)
	{
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,RSA_R_BLOCK_TYPE_IS_NOT_01);
#endif
		return(-1);
	}
	
	 /*scan over padding data*/
	r = i - 1; /*one for type*/

	for (i = 0; i < r; i++)
	{
		if (*p != 0xff)  /* should decrypt to 0xff */
		{
			if (*p == 0)
			{
				p++; 
				break;
			}
			else
			{
#ifndef NO_SSLEAY_ERROR
				RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,RSA_R_BAD_FIXED_HEADER_DECRYPT);
#endif
				return(-1);
			}
		}
		p++;
	}
	
	if (i == r)
	{
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,RSA_R_NULL_BEFORE_BLOCK_MISSING);
#endif
		return(-1);
	}
	
	if (i < 8)
	{
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,RSA_R_BAD_PAD_BYTE_COUNT);
#endif
		return(-1);
	}
	
	i++;  /*skip over the '\0'*/
	r-=i;
	SMemcpy(to, p, (CrUINT32)r);
	
	if (r < 0)
	{
#ifndef NO_SSLEAY_ERROR
		RSAerr(RSA_F_RSA_EAY_PUBLIC_DECRYPT,RSA_R_PADDING_CHECK_FAILED);	
#endif
	}
err:
	if (ctx != NULL)
		BN_CTX_free(ctx);
	if (f != NULL)
		BN_free(f);
	if (ret != NULL)
		BN_free(ret);
	if (buf != NULL)
	{
		SMemset(buf,0,num);
		SFree(buf);
	}
	return(r);
}

 /**
 *	RSA_eay_mod_exp
 *	RETURN VALUE
 *		SUCCESS	: 1
 *		FAILURE	: -1
 */

static CrINT32
RSA_eay_mod_exp(
	BIGNUM*	r0,
	BIGNUM*	I,
	RSA*	rsa)
{
	BIGNUM *r1=NULL,*m1=NULL;
	CrINT32 ret=0;
	BN_CTX *ctx;

	if ((ctx=BN_CTX_new()) == NULL)
		goto err;
	m1=BN_new();
	r1=BN_new();
	if ((m1 == NULL) || (r1 == NULL))
		goto err;

	if (rsa->flags & RSA_FLAG_CACHE_PRIVATE)
	{
		if (rsa->method_mod_p == NULL)
		{
			if ((rsa->method_mod_p=(CrINT8 *)BN_MONT_CTX_new()) != NULL)
				if (!BN_MONT_CTX_set((BN_MONT_CTX *)rsa->method_mod_p,rsa->p,ctx))
					goto err;
		}
		if (rsa->method_mod_q == NULL)
		{
			if ((rsa->method_mod_q=(CrINT8 *)BN_MONT_CTX_new()) != NULL)
				if (!BN_MONT_CTX_set((BN_MONT_CTX *)rsa->method_mod_q,rsa->q,ctx))
					goto err;
		}
	}


	// step 1.
	if (!BN_mod(r1,I,rsa->q,ctx))
		goto err;

	// step 2.
	if (!rsa->meth->bn_mod_exp(m1,r1,rsa->dmq1,rsa->q,ctx,(BN_MONT_CTX*)rsa->method_mod_q))
		goto err;

	// step 3.
	if (!BN_mod(r1,I,rsa->p,ctx))
		goto err;

	// step 4.
	if (!rsa->meth->bn_mod_exp(r0,r1,rsa->dmp1,rsa->p,ctx,(BN_MONT_CTX*)rsa->method_mod_p))
		goto err;

	// step 5.
	if (!BN_add(r1,r0,rsa->p))
		goto err;

	// step 6.
	if (!BN_sub(r0,r1,m1))
		goto err;

	// step 7.
	if (!BN_mul(r1,r0,rsa->iqmp))
		goto err;

	// step 8.
	if (!BN_mod(r0,r1,rsa->p,ctx))
		goto err;

	// step 9.
	if (!BN_mul(r1,r0,rsa->q))
		goto err;

	// step 10.
	if (!BN_add(r0,r1,m1))
		goto err;

	ret=1;

err:
	if (m1 != NULL)
		BN_free(m1);
	if (r1 != NULL)
		BN_free(r1);
	BN_CTX_free(ctx);

	return(ret);
}

 /**
 *Taesung Kim Deleted (2001/1/31)
 *	The init and finish is commented by Taesung Kim
 *	There is no need to running the init and finish functions in TLS.
 */
#if 0
static CrINT32 RSA_eay_init(rsa)
RSA *rsa;
	{
	rsa->flags|=RSA_FLAG_CACHE_PUBLIC|RSA_FLAG_CACHE_PRIVATE;
	return(1);
	}

static CrINT32 RSA_eay_finish(rsa)
RSA *rsa;
	{
	if (rsa->method_mod_n != NULL)
		BN_MONT_CTX_free((BN_MONT_CTX *)rsa->method_mod_n);
	if (rsa->method_mod_p != NULL)
		BN_MONT_CTX_free((BN_MONT_CTX *)rsa->method_mod_p);
	if (rsa->method_mod_q != NULL)
		BN_MONT_CTX_free((BN_MONT_CTX *)rsa->method_mod_q);
	return(1);
	}
#endif // #if 0
	
#endif // #ifdef CR_RSA
