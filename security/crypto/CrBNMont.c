 /* crypto/bn/bn_mont.c */

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



#include "crypto/CrBNConfig.h"

#ifdef _BN_MONT_C



//#include <stdio.h>

#include "crypto/CrSMemMgr.h"

#include "crypto/CrBN.h"

#include "crypto/CrBNLcl.h"



#ifdef DEBUG_TAESUNG

#include "crypto/DebugPrint.h"

extern CrINT32	check_num;

#endif



CrINT32

BN_mod_mul_montgomery(

	BIGNUM*			r,

	BIGNUM*			a,

	BIGNUM*			b,

	BN_MONT_CTX*	mont,

	BN_CTX*			ctx)

{

	BIGNUM *tmp;



        tmp=ctx->bn[ctx->tos++];



	if (a == b)

	{

		if (!BN_sqr(tmp,a,ctx))

			goto err;

#ifdef DEBUG_TAESUNG

		if (check_num == 8)

		{

			printf("============= BN_mod_mul_montgomery ==============\n");

			PrintBN2Hex(tmp, (CrUINT8*)"tmp");

			PrintBN2Hex(a, (CrUINT8*)"a");		

		}

#endif	

	}

	else

	{

		if (!BN_mul(tmp,a,b))

			goto err;

	}







	 /* reduce from aRR to aR */

	if (!BN_from_montgomery(r,tmp,mont,ctx))

		goto err;

#ifdef DEBUG_TAESUNG

		if (check_num == 8)

			PrintBN2Hex(r, (CrUINT8*)"r");

#endif



	



	ctx->tos--;

	

	return(1);



err:

	return(0);

}





#if 1



 /**

 *	2001.07.05 Modified by Taesung Kim.

 *	If the least significant word(LSW) of modulus is '1', then 

 *	result error. In BN_MONT_CTX_set function, which is the part

 *	of precomputation, unexpected data is made.

 *	So I put the check routine in BN_MONT_CTX_set function.

 *	If LSW is 1, then mont->Ni will be set.

 *	After BN_MONT_CTX structure is initialized by using BN_MONT_CTX_set

 *	function, if mont->Ni isn't null, then excute routine not defined MONT_WORD

 *	in original source.

 *	

 *	Search Key Word : [MONT_WORD]

 */

//#define MONT_WORD

//#ifdef MONT_WORD

CrINT32

BN_from_montgomery(

	BIGNUM*			ret,

	BIGNUM*			a,

	BN_MONT_CTX*	mont,

	BN_CTX*			ctx)

{



	CrINT32 retn=0;

	BIGNUM *t1, *r;



	// inserted by dongjin(2000/7/19)

	bn_fix_top(a);

	if (a->top == 0)

	{ 

		ret->top=0; 

		return(1);

	}

	

	t1=ctx->bn[ctx->tos];

	r=ctx->bn[ctx->tos+1];



	if (mont->Ni == NULL)

	{

		{

		BIGNUM *n;

		BN_ULONG *ap,*np,*rp,n0,v;

		CrINT32 al,nl,max,i,x,ri;



		if (!BN_copy(r,a)) goto err;

		n=mont->N;



		ap=a->d;

		 /* mont->ri is the size of mont->N in bits/words */

		al=ri=mont->ri/BN_BITS2;



		nl=n->top;

	//	if ((al == 0) || (nl == 0)) { r->top=0; return(1); }

		if ((al == 0) || (nl == 0)) { ret->top=0; return(1); }



		max=(nl+al+1);  /* allow for overflow (no?) XXX */

		if (bn_wexpand(r,max) == NULL) goto err;

		if (bn_wexpand(ret,max) == NULL) goto err;



		r->neg=a->neg^n->neg;

		np=n->d;

		rp=r->d;



		 /* clear the top words of T */

#if 1

		for (i=r->top; i<max; i++)  /* memset? XXX */

			r->d[i]=0;

#else

		SMemset(&(r->d[r->top]),0,(max-r->top)*sizeof(BN_ULONG)); 

#endif



		r->top=max;

		n0=mont->n0;



		for (i=0; i<nl; i++)

		{

#if 0

			CrINT32 x1,x2;



			if (i+4 > nl)

			{

				x2=nl;

				x1=0;

			}

			else

			{

				x2=i+4;

				x1=nl-x2;

			}



			v=bn_mul_add_words(&(rp[x1]),&(np[x1]),x2,(rp[x1]*n0)&BN_MASK2);

#else

			v=bn_mul_add_words(rp,np,nl,(rp[0]*n0)&BN_MASK2);

#endif



			if (((rp[nl]+=v)&BN_MASK2) < v)

			{

				for (x=(nl+1); (((++rp[x])&BN_MASK2) == 0); x++);

			}

			

			rp++;

		}

		

		while (r->d[r->top-1] == 0)

			r->top--;



		 /* mont->ri will be a multiple of the word size */

#if 0

		BN_rshift(ret,r,mont->ri);

#else

		ap=r->d;

		rp=ret->d;

		x=ri;

		al=r->top-x;

		for (i=0; i<al; i++)

		{

			rp[i]=ap[i+x];

		}

		ret->top=al;

#endif



		if (BN_ucmp(ret,mont->N) >= 0)

		{

			bn_qsub(ret,ret,mont->N);  /* XXX */

		}

		retn=1;



		}

	}

	else

	{

		{

		if (!BN_copy(t1,a)) goto err;

		 /* can cheat */

		BN_mask_bits(t1,mont->ri);



		if (!BN_mul(r,t1,mont->Ni)) goto err;

		BN_mask_bits(r,mont->ri);



		if (!BN_mul(t1,r,mont->N)) goto err;

		if (!BN_add(r,a,t1)) goto err;

		BN_rshift(ret,r,mont->ri);



		if (BN_ucmp(ret,mont->N) >= 0)

			bn_qsub(ret,ret,mont->N);



		retn = 1;

		}

	}

err:

		return(retn);

}

#else

CrINT32

BN_from_montgomery(

	BIGNUM*			r,

	BIGNUM*			a,

	BN_MONT_CTX*	mont,

	BN_CTX*			ctx)

{

	BIGNUM *t1,*t2;



	t1=ctx->bn[ctx->tos];

	t2=ctx->bn[ctx->tos+1];



	if (!BN_copy(t1,a)) goto err;

	 /* can cheat */

	BN_mask_bits(t1,mont->ri);



	if (!BN_mul(t2,t1,mont->Ni)) goto err;

	BN_mask_bits(t2,mont->ri);



	if (!BN_mul(t1,t2,mont->N)) goto err;

	if (!BN_add(t2,a,t1)) goto err;

	BN_rshift(r,t2,mont->ri);



	if (BN_ucmp(r,mont->N) >= 0)

		bn_qsub(r,r,mont->N);



	return(1);

err:

	return(0);

}

#endif // #if 1



BN_MONT_CTX*

BN_MONT_CTX_new()

{

	BN_MONT_CTX *ret;



	if ((ret=(BN_MONT_CTX *)SMalloc(sizeof(BN_MONT_CTX))) == NULL)

		return(NULL);



	ret->ri=0;

	ret->RR=BN_new();

	ret->N=BN_new();

	ret->Ni=NULL;



	if ((ret->RR == NULL) || (ret->N == NULL))

	{

		BN_MONT_CTX_free(ret);

		return(NULL);

	}

	

	return(ret);

}



// modified by dongjin(2000/7/29)

void

BN_MONT_CTX_free(BN_MONT_CTX *mont)

{

	if (mont == NULL)

		return;

	BN_free(mont->RR);

	BN_free(mont->N);

	BN_free(mont->Ni);



	SFree(mont);

}

 /**

 *					    Called 1 times.   SWC_ECC_PT_GFp_Mult()

 *TLS_CLASS1

 */



 /**

 *	2001.07.05 Modified by Taesung Kim.

 *	If the least significant word(LSW) of modulus is '1', then 

 *	result error. In BN_MONT_CTX_set function, which is the part

 *	of precomputation, unexpected data is made.

 *	So I put the check routine in BN_MONT_CTX_set function.

 *	If LSW is 1, then mont->Ni will be set.

 *	After BN_MONT_CTX structure is initialized by using BN_MONT_CTX_set

 *	function, if mont->Ni isn't null, then excute routine not defined MONT_WORD

 *	in original source.

 *	

 *	Search Key Word : [MONT_WORD]

 */



CrINT32

BN_MONT_CTX_set(BN_MONT_CTX *mont,BIGNUM *mod,BN_CTX *ctx)

{

	BIGNUM *Ri=NULL,*R=NULL;



	if (mont->RR == NULL)

		mont->RR=BN_new();

	if (mont->N == NULL)

		mont->N=BN_new();



	R=mont->RR;					 /* grab RR as a temp */

	BN_copy(mont->N,mod);				 /* Set N */



	if (mod->d[0] != 1)

	{

		{

		BIGNUM tmod;

		BN_ULONG buf[2];

		 /* CrINT32 z; */



		mont->ri=(BN_num_bits(mod)+(BN_BITS2-1))/BN_BITS2*BN_BITS2;

		BN_lshift(R,BN_value_one(),BN_BITS2);		 /* R */

		 /* I was bad, this modification of a passed variable was

		 * breaking the multithreaded stuff :-(

		 * z=mod->top;

		 * mod->top=1; */



		buf[0]=mod->d[0];

		buf[1]=0;

		tmod.d=buf;

		tmod.top=1;

		tmod.max=mod->max;

		tmod.neg=mod->neg;



		if ((Ri=BN_mod_inverse(R,&tmod,ctx)) == NULL) goto err;  /* Ri */

		BN_lshift(Ri,Ri,BN_BITS2);			 /* R*Ri */

		bn_qsub(Ri,Ri,BN_value_one());			 /* R*Ri - 1 */

		BN_div(Ri,NULL,Ri,&tmod,ctx);

		mont->n0=Ri->d[0];

		BN_free(Ri);

		 /* mod->top=z; */

		}	

	}

	else

	{

		mont->ri=BN_num_bits(mod);

		BN_lshift(R,BN_value_one(),mont->ri);			 /* R */

		if ((Ri=BN_mod_inverse(R,mod,ctx)) == NULL)

			goto err;	 /* Ri */

		BN_lshift(Ri,Ri,mont->ri);				 /* R*Ri */

		bn_qsub(Ri,Ri,BN_value_one());				 /* R*Ri - 1 */

		BN_div(Ri,NULL,Ri,mod,ctx);

		if (mont->Ni != NULL)

			BN_free(mont->Ni);

		mont->Ni=Ri;					 /* Ni=(R*Ri-1)/N */	

	}



#if 0

#ifdef MONT_WORD

{

	BIGNUM tmod;

	BN_ULONG buf[2];

	 /* CrINT32 z; */



	mont->ri=(BN_num_bits(mod)+(BN_BITS2-1))/BN_BITS2*BN_BITS2;

	BN_lshift(R,BN_value_one(),BN_BITS2);		 /* R */

	 /* I was bad, this modification of a passed variable was

	 * breaking the multithreaded stuff :-(

	 * z=mod->top;

	 * mod->top=1; */



	buf[0]=mod->d[0];

	buf[1]=0;

	tmod.d=buf;

	tmod.top=1;

	tmod.max=mod->max;

	tmod.neg=mod->neg;



	if ((Ri=BN_mod_inverse(R,&tmod,ctx)) == NULL) goto err;  /* Ri */

	BN_lshift(Ri,Ri,BN_BITS2);			 /* R*Ri */

	bn_qsub(Ri,Ri,BN_value_one());			 /* R*Ri - 1 */

	BN_div(Ri,NULL,Ri,&tmod,ctx);

	mont->n0=Ri->d[0];

	BN_free(Ri);

	 /* mod->top=z; */

}

#else // #ifdef MONT_WORD

	mont->ri=BN_num_bits(mod);

	BN_lshift(R,BN_value_one(),mont->ri);			 /* R */

	if ((Ri=BN_mod_inverse(R,mod,ctx)) == NULL)

		goto err;	 /* Ri */

	BN_lshift(Ri,Ri,mont->ri);				 /* R*Ri */

	bn_qsub(Ri,Ri,BN_value_one());				 /* R*Ri - 1 */

	BN_div(Ri,NULL,Ri,mod,ctx);

	if (mont->Ni != NULL)

		BN_free(mont->Ni);

	mont->Ni=Ri;					 /* Ni=(R*Ri-1)/N */

#endif // #ifdef MONT_WORD

#endif // #if 0

	 /* setup RR for conversions */

	BN_lshift(mont->RR,BN_value_one(),mont->ri*2);

	BN_mod(mont->RR,mont->RR,mont->N,ctx);



	return(1);

err:

	return(0);

}



#endif //end of #ifdef _BN_MONT_C




