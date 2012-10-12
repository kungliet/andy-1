 /* crypto/bn/bn_gcd.c */

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

#ifdef _BN_GCD_C



//#include <stdio.h> // for NULL

#include "crypto/CrBN.h"

#include "crypto/CrBNLcl.h"





#ifndef NOPROTO

static BIGNUM *euclid(BIGNUM *a, BIGNUM *b);

#else

static BIGNUM *euclid();

#endif





//#define DEBUG_BELONMY2

#ifdef DEBUG_BELONMY2

#include "crypto/DebugPrint.h"

extern CrINT32	check_num_CrECSPDSA;

CrINT32			check_while_num = 0;

#endif





CrINT32 BN_gcd(BIGNUM *r, BIGNUM *in_a, BIGNUM *in_b, BN_CTX *ctx)

{

	BIGNUM *a,*b,*t;

	CrINT32 ret=0;



	a=ctx->bn[ctx->tos];

	b=ctx->bn[ctx->tos+1];



	if (BN_copy(a,in_a) == NULL) goto err;

	if (BN_copy(b,in_b) == NULL) goto err;



	if (BN_cmp(a,b) < 0) { t=a; a=b; b=t; }

	t=euclid(a,b);

	if (t == NULL) goto err;



	if (BN_copy(r,t) == NULL) goto err;

	ret=1;

err:

	return(ret);

	}



static BIGNUM *euclid(BIGNUM *a, BIGNUM *b)

{

	BIGNUM *t;

	CrINT32 shifts=0;



	for (;;)

		{

		if (BN_is_zero(b))

			break;



		if (BN_is_odd(a))

			{

			if (BN_is_odd(b))

				{

				if (!BN_sub(a,a,b)) goto err;

				if (!BN_rshift1(a,a)) goto err;

				if (BN_cmp(a,b) < 0)

					{ t=a; a=b; b=t; }

				}

			else		 /* a odd - b even */

				{

				if (!BN_rshift1(b,b)) goto err;

				if (BN_cmp(a,b) < 0)

					{ t=a; a=b; b=t; }

				}

			}

		else			 /* a is even */

			{

			if (BN_is_odd(b))

				{

				if (!BN_rshift1(a,a)) goto err;

				if (BN_cmp(a,b) < 0)

					{ t=a; a=b; b=t; }

				}

			else		 /* a even - b even */

				{

				if (!BN_rshift1(a,a)) goto err;

				if (!BN_rshift1(b,b)) goto err;

				shifts++;

				}

			}

		}

	if (shifts)

		{

		if (!BN_lshift(a,a,shifts)) goto err;

		}

	return(a);

err:

	return(NULL);

	}



 /* solves ax == 1 (mod n) */

BIGNUM *BN_mod_inverse(BIGNUM *a, BIGNUM *n, BN_CTX *ctx)

{

	BIGNUM *A,*B,*X,*Y,*M,*D,*R;

	BIGNUM *ret=NULL,*T;

	CrINT32 sign;



	A=ctx->bn[ctx->tos];

	B=ctx->bn[ctx->tos+1];

	X=ctx->bn[ctx->tos+2];

	D=ctx->bn[ctx->tos+3];

	M=ctx->bn[ctx->tos+4];

	Y=ctx->bn[ctx->tos+5];

	ctx->tos+=6;

	R=BN_new();

	if (R == NULL) goto err;





	BN_zero(X);

	BN_one(Y);

	if (BN_copy(A,a) == NULL) goto err;



	if (BN_copy(B,n) == NULL) goto err;



	sign=1;



	while (!BN_is_zero(B))

		{



		if (!BN_div(D,M,A,B,ctx)) goto err;



		T=A;

		A=B;

		B=M;

		 /* T has a struct, M does not */



		if (!BN_mul(T,D,X)) goto err;



		if (!BN_add(T,T,Y)) goto err;



		M=Y;

		Y=X;

		X=T;

		sign= -sign;

	}



	if (sign < 0)

		{

		if (!BN_sub(Y,n,Y)) goto err;

		}



	if (BN_is_one(A))

		{ if (!BN_mod(R,Y,n,ctx)) goto err; }

	else

		{

#ifndef NO_SSLEAY_ERROR

		BNerr(BN_F_BN_MOD_INVERSE,BN_R_NO_INVERSE);

#endif

		goto err;

		}

	ret=R;

err:

	if ((ret == NULL) && (R != NULL)) BN_free(R);

	ctx->tos-=6;

	return(ret);

	}

 /**

 *					    Called 2 times.   SWC_ECC_PT_GFp_Mult()

 *TLS_CLASS1

 */

 /* solves ax == 1 (mod n) */

CrINT32 BN_mod_inverse_kyung(

	BIGNUM *inverse,

	BIGNUM *a,

	BIGNUM *n,

	BN_CTX *ctx)

{

	BIGNUM *A,*B,*X,*Y,*M,*D,*R;

//	BIGNUM *ret=NULL,*T;

	BIGNUM *T;

	CrINT32 sign;

	CrINT32 retValue = 0; //error



	A=ctx->bn[ctx->tos];

	B=ctx->bn[ctx->tos+1];

	X=ctx->bn[ctx->tos+2];

	D=ctx->bn[ctx->tos+3];

	M=ctx->bn[ctx->tos+4];

	Y=ctx->bn[ctx->tos+5];

	ctx->tos+=6;

	R = inverse;



	BN_zero(X);

	BN_one(Y);

	if (BN_copy(A,a) == NULL) goto err;

	if (BN_copy(B,n) == NULL) goto err;

	sign=1;



#ifdef DEBUG_BELONMY2

	if (check_num_CrECSPDSA == 1)

	{

		PrintBN2Hex(A, (CrINT8*)"A");

		PrintBN2Hex(B, (CrINT8*)"B");

	}

#endif

	while (!BN_is_zero(B))

	{

#ifdef DEBUG_BELONMY2

		if (check_num_CrECSPDSA == 1)

		{

			check_while_num++;

			printf("======== Number of while loop = %d ========\n", check_while_num);

			printf("Before BN_div(D,M,A,B,ctx);\n");

			PrintBN2Hex(D, (CrINT8*)"D");

			PrintBN2Hex(M, (CrINT8*)"M");

		}

#endif

		if (!BN_div(D,M,A,B,ctx)) goto err;		// 가장 시간이 오래 걸림

#ifdef DEBUG_BELONMY2

		if (check_num_CrECSPDSA == 1)

		{

			printf("After BN_div(D,M,A,B,ctx);\n");

			PrintBN2Hex(D, (CrINT8*)"D");

			PrintBN2Hex(M, (CrINT8*)"M");

		}

#endif

		T=A;

		A=B;

		B=M;

		// T has a struct, M does not

#ifdef DEBUG_BELONMY2

		if (check_num_CrECSPDSA == 1)

		{

			printf("Before BN_mul(T,D,X);\n");

			PrintBN2Hex(T, (CrINT8*)"T");

		}

#endif

		if (!BN_mul(T,D,X)) goto err;

#ifdef DEBUG_BELONMY2

		if (check_num_CrECSPDSA == 1)

		{

			printf("After BN_mul(T,D,X);\n");

			PrintBN2Hex(T, (CrINT8*)"T");

			printf("Before BN_add(T,T,Y);\n");

			PrintBN2Hex(T, (CrINT8*)"T");

		}

#endif

		if (!BN_add(T,T,Y)) goto err;

#ifdef DEBUG_BELONMY2

		if (check_num_CrECSPDSA == 1)

		{

			printf("After BN_add(T,T,Y);\n");

			PrintBN2Hex(T, (CrINT8*)"T");

		}

#endif



		M=Y;

		Y=X;

		X=T;

		sign= -sign;

	}

	if (sign < 0)

	{

		if (!BN_sub(Y,n,Y)) 

			goto err;

	}

	if (BN_is_one(A))

	{ 

		if (!BN_mod(R,Y,n,ctx)) 

			goto err; 

	}

	else

		{

#ifndef NO_SSLEAY_ERROR

		BNerr(BN_F_BN_MOD_INVERSE,BN_R_NO_INVERSE);

#endif

		goto err;

		}

	retValue = 1; //success

err:

	//if ((ret == NULL) && (R != NULL)) BN_free(R);

	ctx->tos-=6;

	return(retValue);

	}



#endif //end of #ifdef _BN_GCD_C



