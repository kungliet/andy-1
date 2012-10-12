 /*
*
* 1999.3.16 Jung Kyung Im modified
*	The authentication key K can be of any length up to B, the block length length 
*	of hash function. Applications that use keys longer than B bytes will first 
*	hash the key using H and then use the resultant L bytes string as the actual key to HMAC
*	Yet, our HMAC function hash the keys longer than B bytes.
*	Applications that use HMAC function don't need to consider the length of keys.
*
* 1999.7.21 Jung Kyung Im modified
*	If you use MD5 hash, define TLS_API_MD5
*		SHA1 is default Hash.
*/


#include "crypto/TlsCrConfig.h"
#ifdef TLS_API_HASH

#include "crypto/CrConfig.h"

#ifdef TLS_API_SHA1
#include "crypto/CrSHA.h"
#endif

#if defined(TLS_API_SHA256) || defined(TLS_API_SHA384) || defined(TLS_API_SHA512)
#include "crypto/CrSHA2.h"
#endif

#ifdef TLS_API_MD2
#include "crypto/CrMD2.h"
#endif

#ifdef TLS_API_MD5
#include "crypto/CrMD5.h"
#endif



#include "crypto/CrSMemMgr.h"
#include "crypto/TlsCrSecurity.h"
//#include "crypto/TlsCrKeySt.h"
#include "crypto/TlsCrHash.h"
#include "crypto/TlsCrMemMgr.h"
#include "crypto/TlsCrError.h"













#define SHA_XOR_40_OUT_SIZE 5
#define CrMAX(A,B) ((A)>(B)?(A):(B))


static void 
TlsCrXOR(
	CrUINT8*	pOut,
	CrUINT8*	pIn,
	CrUINT16	uInSize,
	CrUINT8		cValue)
{
	CrUINT16 i;

	for (i=0; i<uInSize; i++)
	{
		*(pOut+i)=(CrUINT8)(*(pIn+i) ^ cValue);
	}
}

static void
TlsCrXORBlock(
	CrUINT8*	pOut,
	CrUINT8*	pIn,
	CrUINT16	uInSize
)
{
	CrUINT16 i;

	for (i=0; i<uInSize; i++) 
	{
		*(pOut+i) ^=  *(pIn +i);
	}
}


static void
TlsSHAXOR40(
	CrUINT8*	pIn,
	CrUINT16	valueSize,
	CrUINT8*	pOut
)
{
	CrUINT8 aBuffer[SHA_XOR_40_OUT_SIZE];
	CrUINT8 aBufferLast[SHA_XOR_40_OUT_SIZE];
	CrINT32 i;
	CrINT32 maxIteration;

	SMemset(aBuffer, MEM_CLEAR_CHAR, SHA_XOR_40_OUT_SIZE);
	SMemset(aBufferLast, MEM_CLEAR_CHAR, SHA_XOR_40_OUT_SIZE);
	
	maxIteration = valueSize / SHA_XOR_40_OUT_SIZE;

	for ( i=0; i < maxIteration; i++ ) 
		TlsCrXORBlock(aBuffer, pIn + i * SHA_XOR_40_OUT_SIZE, SHA_XOR_40_OUT_SIZE);

	if ( valueSize % SHA_XOR_40_OUT_SIZE) 
	{
		SMemcpy(aBufferLast, pIn +i * SHA_XOR_40_OUT_SIZE, valueSize - i * SHA_XOR_40_OUT_SIZE);
		TlsCrXORBlock(aBuffer, aBufferLast, SHA_XOR_40_OUT_SIZE);
	}

	SMemcpy(pOut, aBuffer, SHA_XOR_40_OUT_SIZE);
}

//Tae-Sung Kim MODIFIED. 00/10/06
 /*parameter type change : (octet -> (pValue, valueSize))*/
//Tae-Sung Kim MODIFIED. 00/10/09
 /*SHA_CTX* add, for the SHA1() func. step process*/
//Tae-Sung Kim MODIFIED. 00/10/10
 /*Func's internal octet type is modified to value and valuesize*/
#if defined(WTLS) || defined(TLS)

TLSCrResult
TlsCrSHA1(
	CrUINT8**		ppOut,		//out
	CrULONG32*		pOutSz,		//out
	SHA_CTX*		pSHA,		//in, out
	CrUINT8*		pIn,		//in
	CrULONG32		uInSz,		//in
	CrINT32			mode		//in
)
{
	CrUINT8*			pTempOut = NULL;
	CrULONG32			uTempOutSz;
	TLSCrResult err = noError;

	if (pSHA == NULL) 
	{
		err = SPtrMalloc((void **)&pSHA, (CrINT32)sizeof(SHA_CTX));
		CHECK_ERROR(err);
	}

	switch (mode) 
	{
		case(TLS_HASH_INIT_MODE):
		{
			SHA1_Init(pSHA);
			return noError;
		}
		case(TLS_HASH_UPDATE_MODE):
		{
			SHA1_Update(pSHA, pIn, uInSz);
			return noError;
		}
		case(TLS_HASH_FINAL_MODE):
		{
			if (*ppOut == NULL) 
			{
				uTempOutSz = SHA_DIGEST_LENGTH;
				err = SPtrMalloc((void **)&pTempOut, sizeof(CrUINT8) * uTempOutSz);
				CHECK_LOCAL_ERROR(err);
			}
			else  
			{
				pTempOut = *ppOut;
				uTempOutSz = SHA_DIGEST_LENGTH;
			}

			SHA1_Final(pTempOut, pSHA);
			
			if (*ppOut == NULL)
				*ppOut = pTempOut;
			*pOutSz = uTempOutSz;

			SMemset(pSHA,0,sizeof(SHA_CTX));
			break;
		}
		default:
		{
			if (*ppOut == NULL) 
			{
				uTempOutSz = SHA_DIGEST_LENGTH;
				err = SPtrMalloc((void **)&pTempOut, (CrINT32)(sizeof(CrUINT8) * uTempOutSz));
				CHECK_LOCAL_ERROR(err);
			}
			else  
			{
				pTempOut = *ppOut;
				uTempOutSz = SHA_DIGEST_LENGTH;
			}
			SHA1(pIn, (CrULONG32)uInSz, pTempOut);
			if (*ppOut == NULL) 
				*ppOut = pTempOut;
			*pOutSz = uTempOutSz;

			SMemset(pSHA,0,sizeof(SHA_CTX));
		}
	}
ERR:
	if (*ppOut == NULL)
		SFree(pTempOut);
	return err;
}

#else


TLSCrResult TlsCrSHA1(
	CrUINT8**		ppOut,
	CrUINT16*		pOutLen,
	CrUINT8*		pIn,
	CrUINT16		uInLen
)
{
	TLSCrResult		err = noError;
	CrUINT8*		pTempOut = NULL;
	CrUINT16		uTempOutLen;

	if (*ppOut == NULL)
	{
		uTempOutLen = SHA_DIGEST_LENGTH;
		err = SPtrMalloc((void **)&pTempOut, (CrINT32)(sizeof(CrUINT8) * uTempOutLen));
		CHECK_ERROR(err);
	}
	else
		pTempOut = *ppOut;
		uTempOutLen = SHA_DIGEST_LENGTH;

	SHA1(pIn, (CrULONG32)uInLen, pTempOut);
	

	if (*ppOut == NULL)
		*ppOut = pTempOut;
	*pOutLen = uTempOutLen;


	if (*ppOut == NULL)
		SFree(pTempOut);

	return err;
}
#endif


/*
 * TlsCrSHA256 is a TLS API function to get SHA 256 digest.
 *
 * @return		result of execution
 * @param
 *
 * @author		Jaejin Choi / 82-2-3416-0627 / jjchoi@samsung.com
 * @history		10/July/2002
 *
 */
#ifdef TLS_API_SHA256
TLSCrResult
TlsCrSHA256(
	CrUINT8**		ppOut,		//out
	CrUINT16*		pOutLen,	//out
	CrUINT8*		pIn,		//in
	CrUINT16		uInLen		//in
)
{
	*pOutLen = SHA256_DIGEST_LENGTH;
	return SHA256(ppOut, pIn, uInLen);
}
#endif

/*
 * TlsCrSHA384 is a TLS API function to get SHA 384 digest.
 *
 * @return		result of execution
 * @param
 *
 * @author		Jaejin Choi / 82-2-3416-0627 / jjchoi@samsung.com
 * @history		10/July/2002
 *
 */
#ifdef TLS_API_SHA384
TLSCrResult
TlsCrSHA384(
	CrUINT8**		ppOut,		//out
	CrUINT16*		pOutLen,	//out
	CrUINT8*		pIn,		//in
	CrUINT16		uInLen		//in
)
{
	*pOutLen = SHA384_DIGEST_LENGTH;
	return SHA384(ppOut, pIn, uInLen);
}
#endif

/*
 * TlsCrSHA512 is a TLS API function to get SHA 512 digest.
 *
 * @return		result of execution
 * @param
 *
 * @author		Jaejin Choi / 82-2-3416-0627 / jjchoi@samsung.com
 * @history		10/July/2002
 *
 */
#ifdef TLS_API_SHA512
TLSCrResult
TlsCrSHA512(
	CrUINT8**		ppOut,		//out
	CrUINT16*		pOutLen,	//out
	CrUINT8*		pIn,		//in
	CrUINT16		uInLen		//in
)
{
	*pOutLen = SHA512_DIGEST_LENGTH;
	return SHA512(ppOut, pIn, uInLen);
}
#endif

#ifdef TLS_API_MD5
TLSCrResult TlsCrMD5(
	CrUINT8**	ppOut,
	CrUINT16*	pOutSz,
	MD5_CTX*	pMD5,
	CrUINT8*	pIn,
	CrUINT16	uInSz,
	CrINT32		mode
)
{
	CrUINT8*	pTempOut;
	CrUINT16	uTempOutSz;
	TLSCrResult err = noError;
	
	if (pMD5 == NULL)
	{
		err = SPtrMalloc((void **)&pMD5, (CrINT32)sizeof(MD5_CTX));
		CHECK_ERROR(err);
	}
	
	switch (mode)
	{
		case(TLS_HASH_INIT_MODE):
		{
			MD5_Init(pMD5);
			return noError;
		}
		case(TLS_HASH_UPDATE_MODE):
		{
			MD5_Update(pMD5, (CrUINT8 *)pIn, (CrULONG32)uInSz);
			return noError;
		}
		case(TLS_HASH_FINAL_MODE):
		{
			if (*ppOut == NULL)
			{
				uTempOutSz = MD5_DIGEST_LENGTH;
				err = SPtrMalloc((void **)&pTempOut, (CrUINT16)(sizeof(CrUINT8) * uTempOutSz));
				CHECK_LOCAL_ERROR(err);
			}
			else
			{
				pTempOut = *ppOut;
				uTempOutSz = MD5_DIGEST_LENGTH;
			}
			
			MD5_Final(pTempOut, pMD5);
			
			if (*ppOut == NULL)
				*ppOut = pTempOut;
			
			*pOutSz = uTempOutSz;
			
			SMemset(pMD5, 0x00, sizeof(MD5_CTX));
			break;
		}
		default:
		{
			if (*ppOut == NULL)
			{
				uTempOutSz = MD5_DIGEST_LENGTH;
				err = SPtrMalloc((void **)&pTempOut, (CrINT32)(sizeof(CrUINT8) * uTempOutSz));
				CHECK_LOCAL_ERROR(err);
			}
			else
			{
				pTempOut = *ppOut;
				uTempOutSz = MD5_DIGEST_LENGTH;
			}

			MD5(pIn, (CrULONG32)uInSz, pTempOut);

			if (*ppOut == NULL)
				*ppOut = pTempOut;
			
			*pOutSz = uTempOutSz;
			
			SMemset(pMD5, 0x00, sizeof(MD5_CTX));
		} // default: end
	} // switch end

ERR:
	if (*ppOut == NULL)
		SFree(pTempOut);
	
	return err;
}
#endif //ifdef TLS_API_MD5



TLSCrResult 
TlsCrHash(
	CrUINT8*			pOut,
	CrUINT16*			pOutSize,
	CrUINT8*			pData,
	CrUINT16			uDataSize,
	TLSMACAlgorithm		iHashParameterIndex)	// in
{
	CrUINT8		aHashOut[MAX_DIGEST_LEN];

	switch (iHashParameterIndex) 
	{
#ifdef TLS_API_SHA1
// Sung-Min... in order to generate 32bits hash value
		case TLS_MAC_SHA_32:
			*pOutSize = 4;
			SHA1(pData, (CrULONG32)uDataSize, aHashOut);
			break;
// Sung-Min

		case TLS_MAC_SHA_40:
			*pOutSize = 5;
			SHA1(pData, (CrULONG32)uDataSize, aHashOut);
			break;
	
		case TLS_MAC_SHA_80:
			*pOutSize = 10;
			SHA1(pData, (CrULONG32)uDataSize, aHashOut);
			break;
		
		case TLS_MAC_SHA:
			*pOutSize = 20;
			SHA1(pData, (CrULONG32)uDataSize, aHashOut);
			break;
	
		case TLS_MAC_SHA_XOR_40:
			*pOutSize = SHA_XOR_40_OUT_SIZE; 
			TlsSHAXOR40(pData, uDataSize, aHashOut);
			break;
#endif

#ifdef TLS_API_SHA256
		/* added by Jaejin Choi */
		case TLS_MAC_SHA_256:
			*pOutSize = SHA256_DIGEST_LENGTH; 
			SHA256((CrUINT8 **) &pHashOut, pData, uDataSize);	// order of parameters is different
			break;
#endif

#ifdef TLS_API_SHA384
		/* added by Jaejin Choi */
		case TLS_MAC_SHA_384:
			*pOutSize = SHA384_DIGEST_LENGTH; 
			SHA384((CrUINT8 **) &pHashOut, pData, uDataSize);	// order of parameters is different
			break;
#endif

#ifdef TLS_API_SHA512
		/* added by Jaejin Choi */
		case TLS_MAC_SHA_512:
			*pOutSize = SHA512_DIGEST_LENGTH; 
			SHA512((CrUINT8 **) &pHashOut, pData, uDataSize);	// order of parameters is different
			break;
#endif

#ifdef TLS_API_MD5
		case TLS_MAC_MD5_40:
			*pOutSize = 5;
			MD5(pData, (CrULONG32)uDataSize, aHashOut);
			break;
	
		case TLS_MAC_MD5_80:
			*pOutSize = 10;
			MD5(pData, (CrULONG32)uDataSize, aHashOut);
			break;
			
		case TLS_MAC_MD5:
			*pOutSize = 16;
			MD5(pData, (CrULONG32)uDataSize, aHashOut);
			break;
#endif //ifdef _SHP_PROTO_CR_MD5
		 /**
		 *	2001.07.10 Added by Taesung Kim.
		 *
		 *	Added MD2 algorithm for SSL.
		 */
#ifdef TLS_API_MD2
		case TLS_MAC_MD2:
			*pOutSize = 16;
			MD2(pData, (CrULONG32)uDataSize, aHashOut);
			break;
#endif // #ifdef TLS_API_MD2
	default:
		return eMacHashAlgorithm;
	}
	
	SMemcpy(pOut, aHashOut, *pOutSize);

	return noError;
}




TLSCrResult
TlsCrConvertHashAlgo(
	TLSMACAlgorithm*	pIOutHashAlgo,
	TLSMACAlgorithm		iInHashAlgo)
{
	TLSCrResult  err = noError;

	switch (iInHashAlgo) 
	{
		case TLS_MAC_SHA_0: 
		case TLS_MAC_SHA_32: 
		case TLS_MAC_SHA_40:
		case TLS_MAC_SHA_80: 
		case TLS_MAC_SHA:
		case TLS_MAC_SHA_XOR_40:
			*pIOutHashAlgo =  TLS_MAC_SHA;
			break;
	
		case TLS_MAC_MD5_40: 
		case TLS_MAC_MD5_80:
		case TLS_MAC_MD5:
			*pIOutHashAlgo =  TLS_MAC_MD5;
			break;
		 /* 2001.07.10 Added by Taesung Kim. Adding MD2 algorithm for SSL */
		case TLS_MAC_MD2:
			*pIOutHashAlgo = TLS_MAC_MD2;
			break;
	
		default:
			return eMacHashAlgorithm;
	}

	return err;
}

//Tae-Sung Kim MODIFIED. 00/10/06
 /*parameter type change : (octet -> (pValue, valueSize))*/
//Tae-Sung Kim MODIFIED. 00/10/10
 /*Func's internal octet type is modified to value and valuesize*/
TLSCrResult
TlsCrHMAC(		
	CrUINT8**				ppHMACOut,
	CrUINT16*				pHMACOutSz,
	CrUINT8*				pKey,
	CrUINT16				uKeySz,
	CrUINT8*				pData,
	CrUINT16				uDataSz,
	TLSMACAlgorithm			iHashParameterIndex	// in
)
{
		
	CrUINT8 aDigest[MAX_DIGEST_LEN];
	CrUINT16 uDigestSize;
	TLSCrResult err = noError; 
	
	CrUINT8*		pTempOut = NULL;
	CrUINT8*		pBuffer = NULL;
	CrUINT8*		pTempKey = NULL;
	CrUINT16		uTempOutSz;
	CrUINT16		uBufferSz;
	CrUINT16		uTempKeySz;
	CrUINT16		mallocedMemorySize;
	TLSMACAlgorithm  iConvertedHashAlgo;

	//1999.10.27 KyungIm Jung modified 
	if (*ppHMACOut == NULL )
	{
		if (iHashParameterIndex == TLS_MAC_SHA_0)
		{
			uTempOutSz = 0;
			*ppHMACOut = pTempOut;
			*pHMACOutSz = uTempOutSz;
			return noError;
		}
		else
		{
			err = TlsCrGetHashSize(&uTempOutSz, iHashParameterIndex);
//			CHECK_LOCAL_ERROR(err);
			CHECK_ERROR(err);

			err = SPtrMalloc((void **)&pTempOut, (CrINT32)(sizeof(CrUINT8) * uTempOutSz));
			CHECK_ERROR(err);
		}
	}
	else
	{
		pTempOut = *ppHMACOut;
		uTempOutSz = *pHMACOutSz;
		if (iHashParameterIndex == TLS_MAC_SHA_0)
		{
			uTempOutSz = 0;
			return noError;
		}
	}
	

	//1999.10.25 KyungIm Jung added SHA_XOR_40
	if (iHashParameterIndex == TLS_MAC_SHA_XOR_40)
	{
		TlsSHAXOR40(pData, uDataSz, pTempOut);
		uTempOutSz = 5;
		
	}
	else
	{
		//1999.11.24 KyungIm Jung added
		//Even though, the hash algorithm is SHA_40, SHA_80, MD5_80, MD5_40
		//HMAC uses internally full length hash result.
		//In case of HMAC output, we truncate the output according to algo. index.
		err = TlsCrConvertHashAlgo(&iConvertedHashAlgo, iHashParameterIndex);
		CHECK_LOCAL_ERROR(err);
			
		 /*	1999.3.16 Jung Kyung Im modified
		* orignal code
		* pBuffer->valueSize = MAC_HASH_BLOCK_LEN + pData->valueSize
		* If pData->valueSize is smaller than hash output length, 
		*	there is access violation error.
		* So I modified as follows.
		*/
		uBufferSz = (CrUINT16)(MAC_HASH_BLOCK_LEN + CrMAX(uDataSz,SHA_DIGEST_LENGTH));
		mallocedMemorySize = uBufferSz;
			
		err = SPtrMalloc((void **)&pBuffer, sizeof(CrUINT8) * uBufferSz);
		CHECK_LOCAL_ERROR(err);

		//step0: by Jung Kyung Im
		//if the key length is more than B bytes, hash the key
		if (uKeySz > MAC_HASH_BLOCK_LEN )
		{
			err = TlsCrGetHashSize(&uTempKeySz, iConvertedHashAlgo);
			CHECK_LOCAL_ERROR(err);

			err = SPtrMalloc((void **)&pTempKey, sizeof(CrUINT8) * uTempKeySz);
			CHECK_LOCAL_ERROR(err);

			err = TlsCrHash(pTempKey, &uTempKeySz, pKey, uKeySz, iConvertedHashAlgo);
			CHECK_LOCAL_ERROR(err);
		}
		else
		{
			pTempKey = pKey;
			uTempKeySz = uKeySz;
		}

		//step1: Append zeros to the end of K to create a B byte string
		//step2: XOR the B byte string computed in step(1) with ipad
		TlsCrXOR(pBuffer, pTempKey, uTempKeySz, IPAD);
		SMemset(pBuffer + uTempKeySz, IPAD, MAC_HASH_BLOCK_LEN - uTempKeySz);
			
		// step3: append the data to the B Byte string resulting from step(2)
		SMemcpy(pBuffer + MAC_HASH_BLOCK_LEN, pData, uDataSz);

		//step4: Apply H to the data generated in step(3)
		//We use full length hash result. So, we use "iConvertedHashAlgo"
		uBufferSz = (CrUINT16)(MAC_HASH_BLOCK_LEN + uDataSz);
		err = TlsCrHash(aDigest, &uDigestSize, pBuffer, uBufferSz, iConvertedHashAlgo);
		CHECK_LOCAL_ERROR(err);

		//step5: XOR the B byte string computed in step(1) with opad
		TlsCrXOR(pBuffer, pTempKey, uTempKeySz, OPAD);
		SMemset(pBuffer + uTempKeySz, OPAD, MAC_HASH_BLOCK_LEN - uTempKeySz);

		//step6: Append the H result from step(4) to the B Byte string
		//resulting from step(5)
		SMemcpy(pBuffer + MAC_HASH_BLOCK_LEN, aDigest, uDigestSize);

		//step7: apply H to the data generated in step(6) and output the result
		//In this case, we use "iHashAlgorithmIndex" because pO->pValue is the 
		//output of the HMAC
		uBufferSz = (CrUINT16)(MAC_HASH_BLOCK_LEN + uDigestSize);
		err = TlsCrHash(pTempOut, &uTempOutSz, pBuffer, uBufferSz, iHashParameterIndex);
		CHECK_LOCAL_ERROR(err);

	}


	if (*ppHMACOut == NULL) 
		*ppHMACOut = pTempOut;

	*pHMACOutSz = uTempOutSz;
	



ERR:
	if ((*ppHMACOut == NULL) && (iHashParameterIndex != TLS_MAC_SHA_0))
		SFree(pTempOut);
	if (pBuffer != NULL)
		SFree(pBuffer);

//	if (pTempKey != pKey) 
	if ((uKeySz > MAC_HASH_BLOCK_LEN))
		SFree(pTempKey);


	return err;	
}




TLSCrResult
TlsCrGetHashSize(
	CrUINT16*			pHashSize,
	TLSMACAlgorithm		iHashParameterIndex)
{
	switch (iHashParameterIndex)
	{
#ifdef TLS_API_SHA1
		case TLS_MAC_SHA_40: case TLS_MAC_SHA_XOR_40:
			*pHashSize = 5;
			return noError;
	
		case TLS_MAC_SHA_80:
			*pHashSize = 10;
			return noError;
		
		case TLS_MAC_SHA:
			*pHashSize = SHA_DIGEST_LENGTH;
			return noError;
#endif
#ifdef TLS_API_MD5
		case TLS_MAC_MD5_40:
			*pHashSize = 5;
			return noError;
	
		case TLS_MAC_MD5_80:
			*pHashSize = 10;
			return noError;
	
		case TLS_MAC_MD5:
			*pHashSize = MD5_DIGEST_LENGTH;
			return noError;
#endif //ifdef _SHP_PROTO_CR_MD5
		 /**
		 *	2001.07.10 Added by Taesung Kim.
		 *	
		 *	Added MD2 algorithm for SSL.
		 */
#ifdef TLS_API_MD2
		case TLS_MAC_MD2:
			*pHashSize = MD2_DIGEST_LENGTH;
			return noError;
#endif // #ifdef TLS_API_MD2
		default:
			return eMacHashAlgorithm;
	}
}

#endif // #if define(TLS_API_SHA1) || defined(TLS_API_MD5)
