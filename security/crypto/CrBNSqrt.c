 /*

*	Finding square roots modulo a prime

*/



#include "crypto/CrBNConfig.h"

#ifdef _BN_SQRT_C



////#include <stdio.h>

#include "crypto/CrBN.h"

#include "crypto/CrBNLcl.h"







 /*



  BN_div를 사용하는 것은 BN_rshift로 대체함 (2000/7, dongjin)



*/

CrINT32 BN_mod_sqrt(

	BIGNUM*	sqrt,

	BIGNUM*	g,

	BIGNUM*	m,

	BN_CTX* ctx)

{

	BIGNUM *A, *B, *C, *D, *E, *P, *delta, *tmp1, *tmp2;

	CrINT32 i;

	CrINT32 retValue = 0; //error



	if ( (m->d[0] & 1) == 0 )

		return (retValue);



	A = ctx->bn[ctx->tos];

	B = ctx->bn[ctx->tos+1];

	C = ctx->bn[ctx->tos+2];

	D = ctx->bn[ctx->tos+3];

	E = ctx->bn[ctx->tos+4];

	P = ctx->bn[ctx->tos+5];

	delta = ctx->bn[ctx->tos+6];

	tmp1 = ctx->bn[ctx->tos+7];

	tmp2 = ctx->bn[ctx->tos+8];

	ctx->tos += 9;







	if ( (m->d[0] & 0x3) == 3) //m = 4k+3

	{

		if (!BN_rshift(A, m, 2))

			goto err;



		if (!BN_add_word(A, 1))

			goto err;



		if (!BN_mod_exp(C, g, A, m, ctx))

			goto err;



		//check solution

		if (!BN_sqr(A, C, ctx))

			goto err;

		

		if (!BN_mod(D, A, m, ctx))

			goto err;



		if (BN_ucmp(D, g))

			goto err;



	}

	else //m = 4k + 1

	{

		if ( (m->d[0] & 0x7) == 5 ) //m = 8k + 5

		{

			if (!BN_rshift(A, m, 3))

				goto err;



			//C = 2g

			if(!BN_lshift1(C, g))

				goto err;



			//D = (2g)^k mod m

			if (!BN_mod_exp(D, C, A, m, ctx))

				goto err;



			//A = D^2

			if (!BN_sqr(A, D, ctx))

				goto err;



			//B = D^2 * 2g mod m 

			if (!BN_mod_mul(B, A, C, m, ctx))

				goto err;



			BN_set_word(A, 1);



			if (!BN_sub(C, B, A))

				goto err;



			if (!BN_mod_mul(A, C, D, m, ctx))

				goto err;



			if (!BN_mod_mul(C, A, g, m, ctx))

				goto err;



			//check solution

			if (!BN_sqr(A, C, ctx))

				goto err;

			

			if (!BN_mod(D, A, m, ctx))

				goto err;



			if (BN_cmp(D, g))

				goto err;



		}

		else  //m = 4k + 1

		{



			if (!BN_rshift(A, m, 1))

				goto err;



			A->d[0] |= 0x1;



			if (!BN_lshift(E, g, 2))

				goto err;



			while (BN_cmp(E, m)>=0)

				bn_qsub(E, E, m);



			do {

				// generate random number(P)

				if (!BN_rand(B, (m->top)*BN_BITS2, 0, 0))

					goto err;



				if (!BN_mod(P, B, m, ctx))

					goto err;



				//

				// generating Lucas Sequence - U(B), V(C), P, 4Q(E)

				//



				// delta = P^2 - 4Q (mod m)

				if (!BN_mod_mul(delta, P, P, m, ctx))

					goto err;



				if (BN_ucmp(delta, E)<=0)

					if (!BN_add(delta, delta, m))

						goto err;

				bn_qsub(delta, delta, E);



				BN_set_word(B, 1);



				if (!BN_copy(C, P))

					goto err;



				for (i=BN_num_bits(A)-2;i>=0;i--) 

				{

		

					if (!BN_mod_mul(tmp2, B, B, m, ctx))

						goto err;



					if (!BN_mod_mul(tmp2, delta, tmp2, m, ctx))

						goto err;



					if (!BN_mod_mul(tmp1, C, C, m, ctx))

						goto err;

					

					if (!BN_add(tmp2, tmp1, tmp2))

						goto err;



					if (BN_ucmp(tmp2, m)>=0)

						bn_qsub(tmp2, tmp2, m);



					if (!BN_mod_mul(B, B, C, m, ctx))

						goto err;



					if (BN_is_odd(tmp2))

						if (!BN_add(tmp2, tmp2, m))

							goto err;

					

					if (!BN_rshift1(C, tmp2))

						goto err;



					if ( BN_is_bit_set(A, i) ) 

					{

						if (!BN_mod_mul(tmp1, P, B, m, ctx))

							goto err;



						if (!BN_add(tmp1, tmp1, C))

							goto err;



						if (BN_ucmp(tmp1, m)>=0)

							bn_qsub(tmp1, tmp1, m);



						if (BN_is_odd(tmp1))

							if (!BN_add(tmp1, tmp1, m))

								goto err;



						if (!BN_mod_mul(tmp2, P, C, m, ctx))

							goto err;



						if (!BN_mod_mul(C, delta, B, m, ctx))

							goto err;



						// set new B(U)

						if (!BN_rshift1(B, tmp1))

							goto err;



						if (!BN_add(C, tmp2, C))

							goto err;

						if (BN_ucmp(C, m)>=0)

							bn_qsub(C, C, m);



						if (BN_is_odd(C))

							if (!BN_add(C, C, m))

								goto err;



						// set new C(V)

						if (!BN_rshift1(C, C))

							goto err;



					}

				}



				if (BN_is_zero(B))

					break;				// find!



				if (BN_is_zero(C))

					goto err;			// no square root exist



			}while (TRUE);



			// C = C/2 mod m

			if (BN_is_odd(C))

				if (!BN_add(C, C, m))

					goto err;

			

			if (!BN_rshift1(C, C))

				goto err;



		}

		

	}

	



	retValue = 1;

	BN_copy(sqrt, C);



err:

	ctx->tos -= 9;

	return retValue;



}



#endif //end of #ifdef BN_SQRT_C



