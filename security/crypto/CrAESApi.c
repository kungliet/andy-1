/**

 * rijndael-api-fst.c

 *

 * @version 2.9 (December 2000)

 *

 * Optimised ANSI C code for the Rijndael cipher (now AES)

 *

 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>

 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>

 * @author Paulo Barreto <paulo.barreto@terra.com.br>

 *

 * This code is hereby placed in the public domain.

 *

 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS

 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED

 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE

 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE

 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR

 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF

 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR

 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,

 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE

 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,

 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 *

 * Acknowledgements:

 *

 * We are deeply indebted to the following people for their bug reports,

 * fixes, and improvement suggestions to this implementation. Though we

 * tried to list all contributions, we apologise in advance for any

 * missing reference.

 *

 * Andrew Bales <Andrew.Bales@Honeywell.com>

 * Markus Friedl <markus.friedl@informatik.uni-erlangen.de>

 * John Skodon <skodonj@webquill.com>

 */



#include "crypto/CrConfig.h"



#ifdef CR_AES

#include "crypto/CrAESAlg.h"

#include "crypto/CrAESApi.h"

#include "crypto/CrSMemMgr.h"











void

makeKey(

	keyInstance*	key, 

	CrINT32			direction, 

	CrINT32			keyLen, 

	CrUINT8*		keyMaterial

)

{

	key->direction = direction;

	key->keyLen = keyLen;



	if (direction == DIR_ENCRYPT)

		key->Nr = rijndaelKeySetupEnc(key->rk, keyMaterial, keyLen);

	else

		key->Nr = rijndaelKeySetupDec(key->rk, keyMaterial, keyLen);



	rijndaelKeySetupEnc(key->ek, keyMaterial, keyLen);

	

	return;

}











void

cipherInit(

	cipherInstance*		cipher,

	CrUINT8				mode,

	CrUINT8*			IV

)

{

	cipher->mode = mode;



	if (IV != NULL)

		SMemcpy(cipher->IV, IV, MAX_IV_SIZE);

	else

		SMemset(cipher->IV, 0, MAX_IV_SIZE);



	return;

}





void

AESEncrypt(

	cipherInstance*		cipher,

	keyInstance*		key,

	CrUINT8*			input,

	CrINT32				inputLen,

	CrUINT8*			outBuffer

)

{

	CrINT32 i, k, t, numBlocks;

	CrUINT8 block[16], *iv;



	numBlocks = inputLen/128;

	

	if (cipher->mode == MODE_ECB)

	{

		for (i = numBlocks; i > 0; i--)

		{

			rijndaelEncrypt(key->rk, key->Nr, input, outBuffer);

			input += 16;

			outBuffer += 16;

		}

	}

	else if (cipher->mode == MODE_CBC)

	{

		iv = cipher->IV;

		for (i = numBlocks; i > 0; i--)

		{

			((CrUINT32*)block)[0] = ((CrUINT32*)input)[0] ^ ((CrUINT32*)iv)[0];

			((CrUINT32*)block)[1] = ((CrUINT32*)input)[1] ^ ((CrUINT32*)iv)[1];

			((CrUINT32*)block)[2] = ((CrUINT32*)input)[2] ^ ((CrUINT32*)iv)[2];

			((CrUINT32*)block)[3] = ((CrUINT32*)input)[3] ^ ((CrUINT32*)iv)[3];

			rijndaelEncrypt(key->rk, key->Nr, block, outBuffer);

			SMemcpy(iv, outBuffer, 16); // bug fixed 2002.5.6

			input += 16;

			outBuffer += 16;

		}

	}

	else //  (cipher->mode == MODE_CFB1)

	{

		iv = cipher->IV;

        for (i = numBlocks; i > 0; i--)

        {

			SMemcpy(outBuffer, input, 16);

            for (k = 0; k < 128; k++)

            {

				rijndaelEncrypt(key->ek, key->Nr, iv, block);

                outBuffer[k >> 3] ^= (block[0] & 0x80U) >> (k & 7);

                for (t = 0; t < 15; t++)

                	iv[t] = (iv[t] << 1) | (iv[t + 1] >> 7);

               	iv[15] = (iv[15] << 1) | ((outBuffer[k >> 3] >> (7 - (k & 7))) & 1);

            }

            outBuffer += 16;

            input += 16;

        }

	}



	

	return ;

}



void

AESDecrypt(

	cipherInstance*	cipher, 

	keyInstance*	key,

	CrUINT8*		input,

	CrINT32			inputLen,

	CrUINT8*		outBuffer

)

{

	CrINT32	 i, k, t, numBlocks;

	CrUINT8 block[16], *iv;



	numBlocks = inputLen/128;



	if (cipher->mode == MODE_ECB)

	{

		for (i = numBlocks; i > 0; i--)

		{

			rijndaelDecrypt(key->rk, key->Nr, input, outBuffer);

			input += 16;

			outBuffer += 16;

		}

	}

	else if (cipher->mode == MODE_CBC)

	{

		iv = cipher->IV;

		for (i = numBlocks; i > 0; i--)

		{

			rijndaelDecrypt(key->rk, key->Nr, input, block);

			((CrUINT32*)block)[0] ^= ((CrUINT32*)iv)[0];

			((CrUINT32*)block)[1] ^= ((CrUINT32*)iv)[1];

			((CrUINT32*)block)[2] ^= ((CrUINT32*)iv)[2];

			((CrUINT32*)block)[3] ^= ((CrUINT32*)iv)[3];

			SMemcpy(cipher->IV, input, 16);

			SMemcpy(outBuffer, block, 16);

			input += 16;

			outBuffer += 16;

		}

	}

	else // cipher->mode == MODE_CFB1

	{

		iv = cipher->IV;

        for (i = numBlocks; i > 0; i--)

        {

			SMemcpy(outBuffer, input, 16);

            for (k = 0; k < 128; k++)

            {

				rijndaelEncrypt(key->ek, key->Nr, iv, block);

                for (t = 0; t < 15; t++)

                	iv[t] = (iv[t] << 1) | (iv[t + 1] >> 7);



               	iv[15] = (iv[15] << 1) | ((input[k >> 3] >> (7 - (k & 7))) & 1);

                outBuffer[k >> 3] ^= (block[0] & 0x80U) >> (k & 7);

            }

            outBuffer += 16;

            input += 16;

        }

	}

	

	return ;

}

#endif // end of #ifdef CR_AES



