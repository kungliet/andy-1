/*	Pseudo Random Function based on ANSI X9.17

*	If you use the arm cpu(PSOS), define __arm in the preprocessor menu.

*	If you use the PC or UNIX, define WIN32 in the preprocessor menu.

*   Written By Jung Kyung Im

*/

#include <CrConfig.h>

#ifdef SWC_RANDOM_NUMBER









//#include "SysMgr.h"

#ifdef SHP_PROJECT_CRYPTO

#	include <TimeMgr.h> // for TmGetElapsedTime function



#	ifdef _SHP_ECOM_CRYPTO

extern ETimeMgr*	pTimeMgr;

#	endif // end of _SHP_ECOM_CRYPTO



#endif // end of SHP_PROJECT_CRYPTO



#include <CrSMemMgr.h>



#if defined(WIN32) || defined(WIN16) || defined(WINDOWS)

#	ifndef MSDOS

#		define MSDOS

#	endif

#endif



#ifdef DEBUG_ARM

#	include <time.h>

CrINT32		numTimeFunc = 1;

#endif



#ifdef UNIX

//#include <unistd.h>

#endif



#ifdef MSDOS

//#include <io.h>

#endif



#ifdef DES_RANDOM

#include <CrDES.h>

#elif defined(RC5_RANDOM)

#include <CrRC5.h>

#include <CrRC5Lcl.h>

#elif defined(AES_RANDOM)

#include <CrAES.h>

#include <CrAESAlg.h>

#include <CrAESApi.h>

#endif



#include <CrSwcRandomLcl.h>



#ifdef WIN32

#include <sys/timeb.h>

#endif

#ifdef XEN
extern CrULONG64 jiffies;
#endif


/* Global Variable & Constant 선언 */

#ifdef DES_RANDOM

	static des_key_schedule ks1;

	static des_key_schedule ks2;

	#define SEED_LEN		8

#elif defined(RC5_RANDOM)

	static RC5_32_KEY		ks1;

	static RC5_32_KEY		ks2;

	#define SEED_LEN		16

#else // In case of AES_128 Random

	static keyInstance		ks1;

	static keyInstance		ks2;

	static cipherInstance	cipher;

	#define SEED_LEN		16

#endif



CrUINT8*		random8Bytes(void);

CrINT32 		makeKey_Seed(void);





static CrUINT8 	seedV[SEED_LEN];

static CrINT32	first_time = 1;



















/*######################################################

 *							xorBlock()

 *######################################################

 */



void 

xorBlock(

	CrUINT8 *output, 

	CrUINT8 *input1, 

	CrUINT8 *input2, 

	CrUINT32 inputLen)

{

	CrUINT32 i;



	for (i=0; i<inputLen; i++) 

	{

		*(output+i)=(CrUINT8)(*(input1+i) ^ *(input2+i));

	}

}





/*######################################################

 *							makeKey_Seed()

 *######################################################

 */



CrINT32 

makeKey_Seed()

{

	CrINT32 status=1;

/**

 *2000/10/17 Tae-Sung Kim modified.

 *Original Code

 *	static CrUINT8 key1[8], key2[8];

 *Because of the key size difference between DES and RC5

 *(DES : 64 bits, RC5 : 128 bits)

 */

#ifdef DES_RANDOM

	static CrUINT8 key1[8], key2[8];

#elif defined(RC5_RANDOM) || defined(AES_RANDOM)//In case of RC5 & AES_128

	static CrUINT8 key1[16], key2[16];

#endif



	CrUINT8 *pTempSeed = NULL;

	

/*seedRandomBytes(key1, 8, REALLY);

	seedRandomBytes(key2, 8, REALLY);

	seedRandomBytes(seedV, 8, REALLY);

*/



/**

 *2000/10/17 Tae-Sung Kim modified.

 *아래의 8이라는 수는 key schedule에 필요한 secret key의 bytes수이다.

 *따라서 des의 경우에는 64bits = 8bytes, RC5-32-xx-16의 경우는 128bits = 16bytes

 *위의 2경우에 대해서 고려해야 하므로 define문을 사용해서 각각의 경우에 대해서 

 *고려해야 한다.



#ifdef DES_RANDOM

#define UKEY 8

#else

#define UKEY 16

#endif



와 같이 선언을 해야 한다. 물론 randomseed.c에서 SEED_LEN을 DES_RANDOM과 

그 외의 경우에 대해서 각각 다르게 정의해야한다. RC5의 경우는 SEED_LEN 16으로 선언

*/

/*original code

	temp = getSeed(NULL);

	SMemcpy(key1, temp, 8);

	

	temp = getSeed(NULL);

	SMemcpy(key2, temp, 8);



	temp = getSeed(NULL);

	SMemcpy(seedV, temp, 8);

	 	

	if (des_key_sched((C_Block *)(key1),ks1) != 0)

		return status;



	if (des_key_sched((C_Block *)(key2),ks2) != 0)

		return status;



	SMemset(key1, 0, 8);

	SMemset(key2, 0, 8);

*/

//2000.11.04 AcMemcpy함수를 comment처리(정경임)



	pTempSeed = getSeed(NULL);

	SMemcpy(key1, pTempSeed, SEED_LEN);

	

	pTempSeed = getSeed(NULL);

	SMemcpy(key2, pTempSeed, SEED_LEN);



	pTempSeed = getSeed(NULL);

	SMemcpy(seedV, pTempSeed, SEED_LEN);





#ifdef DES_RANDOM	 	

	if (des_key_sched((C_Block *)(key1),ks1) != 0)

		return status;



	if (des_key_sched((C_Block *)(key2),ks2) != 0)

		return status;

#elif defined(RC5_RANDOM) //In case of RC5

	RC5_32_set_key(&ks1,16,key1,RC5_12_ROUNDS);

	if(ks1.rounds != 12)

		return status;

 

	RC5_32_set_key(&ks2,16,key2,RC5_12_ROUNDS);



	if(ks2.rounds != 12)

		return status;

#elif defined(AES_RANDOM) // In case of AES random number

	makeKey(&ks1, DIR_ENCRYPT, 128, key1);

	makeKey(&ks2, DIR_DECRYPT, 128, key2);

	cipherInit(&cipher, MODE_ECB, NULL);

#endif



	SMemset(key1, 0, SEED_LEN);

	SMemset(key2, 0, SEED_LEN);

//END

	first_time=0;



	return (status= 0);

}




////////////////////////////////////////////////////////////////////

/*random8Bytes()*/

////////////////////////////////////////////////////////////////////

/*

*Warning: 'p_ticks' may be used before being set

*ARM컴파일시 위와 같은 warning메시지가 나오는 이유는 함수에서

*이 변수를 초기화 시키지 않고 사용하기 때문이다. 그러나 굳이 이렇게

*코딩을 한 이유는, garbage값을 얻기 위함이다.

*/

CrUINT8* random8Bytes()

{

	CrUINT8 dt[SEED_LEN], temp1[SEED_LEN], temp2[SEED_LEN], temp3[SEED_LEN];

	CrUINT8 *random;



#ifdef UNIX
#ifndef XEN
	struct timeval u_time;
#else
	// don't care... in case of XEN, it will use jiffies_64 which is a global variable.
#endif

#else

	struct _timeb timebuffer;

#endif

	//time_t ltime;







	if (first_time)

		if (makeKey_Seed() == 1 )

			return NULL;

	random=(CrUINT8 *)SMalloc(sizeof(CrUINT8)*8);



	if (random == NULL )

		return NULL;



#ifdef UNIX

#ifdef XEN

	SMemcpy(dt, (CrUINT8 *)&(jiffies), 4);
	
	SMemcpy(&dt[4], (CrUINT8 *)&(jiffies) + 4, 4);

#else

	gettimeofday(&u_time, NULL);



	SMemcpy(dt, (CrUINT8 *)&(u_time.tv_sec), 4);

	SMemcpy(&dt[4], (CrUINT8 *)&(u_time.tv_usec),4); 

#endif

#else

	// fill dt[8]

	_ftime(&timebuffer);

	/*  dt[4],[5] are NOT initialized. Result Error */

	SMemcpy(dt, (CrUINT8 *)&(timebuffer.time), 4); 

	/* dt[4] = 0x00; dt[5] = 0x00; */

	SMemcpy(&dt[6], (CrUINT8 *)&(timebuffer.millitm), 2);

	//need to be hashed

#endif





	// dt -> temp1

	AESEncrypt(&cipher, &ks1, dt, SEED_LEN*8, temp1);

	AESDecrypt(&cipher, &ks2, temp1, SEED_LEN*8, dt);

	AESEncrypt(&cipher, &ks1, dt, SEED_LEN*8, temp1);



	// temp2 = temp1 ^ seedV

	xorBlock(temp2, temp1, seedV, SEED_LEN);



	// temp2 -> temp3

	AESEncrypt(&cipher, &ks1, temp2, SEED_LEN*8, temp3);

	AESDecrypt(&cipher, &ks2, temp3, SEED_LEN*8, temp2);

	AESEncrypt(&cipher, &ks1, temp2, SEED_LEN*8, temp3);



	SMemcpy(random, temp3, 8);



	// temp2 = temp1 ^ temp3

	xorBlock(temp2, temp1, temp3, SEED_LEN);

	

	// temp2 -> seedV

	AESEncrypt(&cipher, &ks1, temp2, SEED_LEN*8, temp1);

	AESDecrypt(&cipher, &ks2, temp1, SEED_LEN*8, temp2);

	AESEncrypt(&cipher, &ks1, temp2, SEED_LEN*8, temp1);



	SMemcpy(seedV, temp1, SEED_LEN);





//END

	SMemset(temp1, 0, SEED_LEN);

	SMemset(temp2, 0, SEED_LEN);



	return random;



}



CrINT32 getRandomBytes(

	CrUINT8 *out,

	CrUINT32 outLen)

{

	CrINT32 i, index, status=1;

	CrUINT8 *random;



	index=(outLen/8);



	for (i=0; i< index; i++) {

		random=random8Bytes();

		if (random == NULL)

			return status;

		SMemcpy(out+8*i, random, 8);

		if (random != NULL)

			SFree (random);

	}

	if (outLen-8*index) {

		random=random8Bytes();

		if (random == NULL)

			return status;

		SMemcpy(out+8*i, random, outLen-8*index);

		if (random != NULL)

			SFree (random);

	}

	return (status=0);



}

/*

CrINT32 SWCGetRandomBits(

	CrUINT8*	pOut,

	CrUINT32	uRandomSizeInBits

	)

{

	CrINT32 status = 0;

	CrUINT8 uRemainedBits;

	CrUINT8 uMaskingByte = 0xff;



	status = getRandomBytes(pOut, (uRandomSizeInBits + 7)/8);

	if (status)

		return status;



	uRemainedBits = uRandomSizeInBits % 8;



	if (uRemainedBits)

	{

		uMaskingByte = 0xff >> (8 - uRemainedBits);

		pOut[0] &= uMaskingByte;

	}



	return (status = 0);





}

*/



#endif // #ifdef SWC_RANDOM_NUMBER



