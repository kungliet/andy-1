#include "crypto/TlsCrConfig.h"
#ifdef TLS_API_RSA


#include "crypto/CrConfig.h"
#include "crypto/CrRSA.h"
#include "crypto/CrSMemMgr.h"
#include "crypto/TlsCrKeySt.h"
#include "crypto/TlsCrSecurity.h"
#include "crypto/TlsCrRSA.h"
#include "crypto/TlsCrSSLeayRSA.h"
#include "crypto/TlsCrError.h"







#define TLS_RANDOM_CLNTVERSION_SIZE 1


/**
 *	##########################################################
 *	Decrypted Values Length are 
 *		WTLS
 *			20(SHA1), 16(MD5), 16(MD2)
 *		SSL
 *			16(MD5) + 20(SHA1) = 36
 *			* 인증서 확인시는 다음과 같이 앞에 ASN.1포맷의 
 *			* 알고리즘에 대한 OID가 붙게 된다.
 *			15(SHA1_ASN) + 20(SHA) = 35
 *			18(MD5_ASN) + 16(MD5) = 34
 *			18(MD2_ASN) + 16(MD2) = 34
 *	##########################################################
 */

// In SSL
#define SIZE_RSA_DECRYPT_WITH_SHA1_IN_SSL		35
#define SIZE_RSA_DECRYPT_WITH_MD_IN_SSL			34

// In WTLS
#define SIZE_RSA_DECRYPT_WITH_SHA1_IN_WTLS		20
#define SIZE_RSA_DECRYPT_WITH_MD5_IN_WTLS		16
#define SIZE_RSA_DECRYPT_WITH_SHA1MD5_IN_WTLS	36

#define SIZE_MAX_RSA_DECRYPT 36
#define DIGEST_INFO_SHA_LEN 20




 /* for sha-1, use the following digestInfo*/
static CrUINT8 
aDIGEST_INFO_SHA[] = 
{
	0x30, 0x21, 
		  0x30, 0x09, 
				0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 
				0x05, 0x00,
		  0x04, 0x14
}; // 15 byte

 /* For MD5, use the following digestInfo */
static CrUINT8 
aDIGEST_INFO_MD5[] = 
{
	0x30, 0x20,
 		0x30, 0x0C,
			0x06, 0x08,0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05,
			0x05, 0x00,
 	0x04, 0x10
}; // 18 byte

static CrUINT8 
aDIGEST_INFO_MD2[] =
{
	0x30, 0x20,
		0x30, 0x0C,
			0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x02,
			0x05, 0x00,
	0x04, 0x10
}; // 18 byte



/**
 * ############################################################################
 * TlsCrGenerateRSAKey
 * ###################
 * @ Description
 *		This function is for the generation of TLS RSA Public/Private Key Pair.
 * ============================================================================
 * @ INPUT
 *		TLSModulusBitsSizeType			modlusBitsSize
 *		: Bit Length of RSA modulus.
 * ============================================================================
 * @ OUTPUT
 *		TLSRSAPrivateKey**				ppRSAPrivateKey
 *		: Pointer to pointer of TLS RSA Private Key Structure.
 *		TLSRSAPrivateKey**				ppRSAPublicKey
 *		: Pointer to pointer of TLS RSA Public Key Structure.
 * ============================================================================
 * @ RETURN
 *		SUCCESS				: noError
 *		FAILURE				: eRSAKeyGenerationFailure
 *							  eNoMoreMemory
 * ############################################################################
 */
TLSCrResult 
TlsCrGenerateRSAKey(
	TLSRSAPrivateKey**		ppRSAPrivateKey,			// out
	TLSRSAPublicKey**		ppRSAPublicKey,				// out
	TLSModulusBitsSizeType	modlusBitsSize				// in
)
{
	RSA*		pRsa = NULL;
	CrULONG32	pE;
	TLSCrResult err;

//	CrINT32		index;
	//public exponent 2^16 +1
	pE=RSA_F4;
	
	if ((pRsa=RSA_generate_key(modlusBitsSize,pE,NULL,NULL)) == NULL)
		return eRSAKeyGenerationFailure;

	err = TlsCrRSAPublicSSLeay2Tls(ppRSAPublicKey, pRsa);
	CHECK_LOCAL_ERROR(err);
		
	err = TlsCrRSAPrivateSSLeay2Tls(ppRSAPrivateKey, pRsa);
	CHECK_LOCAL_ERROR(err);
	

ERR:
	RSA_free(pRsa);
	return err;
}




/**
 * ############################################################################
 * TlsCrRSAPuEnc
 * #############
 * @ Description
 *		This function is for the RSA Encryption.
 * ============================================================================
 * @ INPUT
 *		CrUINT8*				pIn
 *			: Pointer to the data to be encrypted.
 *		CrUINT16				uInLen
 *			: Byte length of the data to be encrypted.
 *		TLSRSAPublicKey*		pPuKey
 *			: Pointer to the TLS RSA Public Key Structure.
 * ============================================================================
 * @ OUTPUT
 *		CrUINT8*				pEncOut
 *			: Pointer to the RSA encrypted data.
 *		CrUINT16*				pEncOutLen
 *			: Pointer to the byte length of the RSA encrypted data.
 * ============================================================================
 * @ RETURN
 *		SUCCESS				: noError
 *		FAILURE				: eNoMoreMemory
 *							  eSSLeayErrN1
 * ============================================================================
 * @ HISTORY
 *
 * ############################################################################
 */
TLSCrResult
TlsCrRSAPuEnc(
	CrUINT8**				ppEncOut,
	CrUINT16*				pEncOutLen,
	CrUINT8*				pIn,
	CrUINT16				uInLen,
	TLSRSAPublicKey*		pPuKey
)
{
	TLSCrResult			err			= noError;
	RSA*				pRsa		= NULL;
	CrUINT8*			pTempOut	= NULL;
	CrUINT16			uTempOutLen;


	 /* 2001.06.12 Modified by Taesung Kim.
	 * 권용석 요청.
	 * 이 함수를 호출하기 전에 output에 대한 메모리가 미리 할당되어 있다.
	 * 하지만 output에 대한 정확한 사이즈를 모르기 때문에 크기에 대해서는 
	 * 설정이 되어 있지 않다.
	 * 그래서 다음과 같이 초기에 output에 대한 메모리가 할당되었던 혹은 
	 * 되었지 않든간에 무조건 미리 output사이즈에 대해서 설정하게 된다.
	 */
	uTempOutLen = pPuKey->modulusSize;

	if (*ppEncOut == NULL)
	{
//		uTempOutLen = pPuKey->modulusSize; // 2001.06.12
		err = SPtrMalloc((void **)&pTempOut, (CrINT32)(sizeof(CrUINT8)*(uTempOutLen)));
		CHECK_ERROR(err); // ERROR : eNoMoreMemory
	}
	else
		pTempOut = *ppEncOut;

	 /* convert TLSRSAPublicKey to SSLeay RSA Key */
	err = TlsCrRSAPublicTls2SSLeay(&pRsa, pPuKey);
	CHECK_LOCAL_ERROR(err);

	 /**
	 *	If there is error, RSA_public_encrypt returns eSSLeayErrN1
	 *	If there is no error, RSA_public_encrypt returns output length
	 *	(output length) == (modulus size)
	 */
	err = (TLSCrResult)RSA_public_encrypt(uInLen, pIn, pTempOut, pRsa, RSA_PKCS1_PADDING);

	 /*	2002.04.20 Modified by Taesung Kim.
	 *	The result size of the RSA_public_encrypt must be less than or same to the modulus size.
	 *	So the result size of the RSA_public_encrypt function is the size of the data to be pointed
	 *	by pTempOut. This size can be less than the modulus size.
	 *	Therefore I modify the following routine
	 *	FROM "err != uTempOutLen" TO "err == eSSLeayErrN1". (where, eSSLeayErrN1 == -1)
	 */
	if ( err == eSSLeayErrN1)
		goto ERR;

	if ( *ppEncOut == NULL)
		*ppEncOut = pTempOut;

	*pEncOutLen = err;

	
	err = noError;


ERR:
	if (*ppEncOut == NULL)
		SFree(pTempOut);

	RSA_free(pRsa);

	return err;
}




/**
 * ############################################################################
 * TlsCrRSAPrDec
 * ############
 * @ DESCRIPTION
 *		This function is for the RSA Private Decryption Operation.
 *		(RSA Private Decryption)
 * ============================================================================
 * @ INPUT
 *		CrINT8*				pEncIn
 *			: Pointer to the RSA Public Encrypted Value.
 *		CrINT16				uEncInLen
 *			: Byte length of the RSA Public Encrypted Value.
 *		TLSRSAPrivateKey*	pRSAPrKey
 *			: Pointer to the TLS RSA Private Key Structure.
 * ============================================================================
 * @ OUTPUT
 *		CrINT8**			ppDecOut
 *			: Pointer of pointer to the RSA Private Decrypted Value.
 *		CrINT16*			pDecOutLen
 *			: Pointer to the byte length of the RSA Private Decrypted Value.
 * ============================================================================
 * @ RETURN
 *		SUCCESS				: noError
 *		FAILURE				: eRSAPrivateTls2SSLeayFailure
 *							  eNoMoreMemory
 *							  eRSAPrivateEncryptionFailure
 * ============================================================================
 * @ HISTORY
 *
 * ############################################################################
 */

TLSCrResult
TlsCrRSAPrDec(
	CrUINT8**				ppDecOut,		// out:	Plain Text
	CrUINT16*				pDecOutLen,		// out:	Plain text length
	CrUINT8*				pEncIn,			// in:	Encrypted Value
	CrUINT16				uEncInLen,		// in:	Encrypted Value Length
	TLSRSAPrivateKey*		pRSAPrKey		// in
)
{
	TLSCrResult			err=noError;
	CrUINT8*			pTempDecOut = NULL;
	CrINT16			uTempDecOutLen;
	RSA*				pSSLeayRSA = NULL;
	
	if (*ppDecOut == NULL)
	{
		uTempDecOutLen = pRSAPrKey->modulusSize; // ex. 1024bits/8 = 128 bytes
		err = SPtrMalloc((void **)&pTempDecOut, sizeof(CrUINT8)*uTempDecOutLen);
		CHECK_ERROR(err);
	}
	else
		pTempDecOut = *ppDecOut;

	 /* convert TLSRSAPrivateKey to SSLeay RSA Key */
	err = TlsCrRSAPrivateTls2SSLeay(&pSSLeayRSA, pRSAPrKey);
	CHECK_LOCAL_ERROR(err);

	// err = length of plain text ('uInLen' in the TlsCrRSAPuEnc function)
	uTempDecOutLen = RSA_private_decrypt(uEncInLen, pEncIn, pTempDecOut, pSSLeayRSA, RSA_PKCS1_PADDING);
	if (uTempDecOutLen == -1)
	{
		err = eRSAPrivateDecryptionFailure;
		goto ERR;
	}

	if (*ppDecOut == NULL)
		*ppDecOut = pTempDecOut;

	*pDecOutLen = uTempDecOutLen;
	
ERR:
	if (*ppDecOut == NULL)
		SFree(pTempDecOut);

	if (pSSLeayRSA != NULL)
		RSA_free(pSSLeayRSA);

	return err;
}

/**
 * ############################################################################
 * TlsCrRSASign
 * ############
 * @ DESCRIPTION
 *		This function is for the RSA Sign Operation.(RSA Private Encryption)
 * ============================================================================
 * @ INPUT
 *		CrINT8*				pHash
 *			: Pointer to the MD5 or SHA1 Hashed Value.
 *		CrINT16				uHashLen
 *			: Byte length of the MD5 or SHA1 Hashed Value.
 *		TLSRSAPrivateKey*	pRSAPrKey
 *			: Pointer to the TLS RSA Private Key Structure.
 * ============================================================================
 * @ OUTPUT
 *		CrINT8**			ppOut
 *			: Pointer of pointer to the RSA Signed Value.
 *		CrINT16*			pOutLen
 *			: Pointer to the byte length of the RSA Signed Value
 * ============================================================================
 * @ RETURN
 *		SUCCESS				: noError
 *		FAILURE				: eRSAPrivateTls2SSLeayFailure
 *							  eNoMoreMemory
 *							  eRSAPrivateEncryptionFailure
 * ============================================================================
 * @ HISTORY
 *
 * ############################################################################
 */

TLSCrResult 
TlsCrRSASign(
	CrUINT8**				ppOut,
	CrUINT32*				pOutLen,
	CrUINT8*				pHash,
	CrUINT32				uHashLen,
	TLSRSAPrivateKey* 		pRSAPrKey
)
{
	TLSCrResult				err			= noError;
	RSA*					pRsa		= NULL;
	CrUINT8*				pTempOut	= NULL;
	CrUINT32				uTempOutLen;

	
	if (*ppOut == NULL)
	{
		uTempOutLen = pRSAPrKey->modulusSize;
		err = SPtrMalloc((void **)&pTempOut, (CrINT32)(sizeof(CrUINT8)*uTempOutLen));
		CHECK_LOCAL_ERROR(err);
	}
	else
	{
		pTempOut = *ppOut;
		uTempOutLen = *pOutLen;
	}
	
	// Convert Format from TLS to SSLeay
	err = TlsCrRSAPrivateTls2SSLeay(&pRsa, pRSAPrKey);
	CHECK_ERROR(err);

	


	// RSA SIGN : RSA Private Encrypt(hash)
	uTempOutLen = (CrUINT32)RSA_private_encrypt(	uHashLen, pHash,	// in
													pTempOut,				 	// out
													pRsa, 						// in
													RSA_PKCS1_PADDING);			// in : fixed value
	
	if (uTempOutLen == 0)
		return eRSAPrivateEncryptionFailure; // <TlsCrError.h>
	
	if (*ppOut == NULL)
		*ppOut = pTempOut;
	
	*pOutLen = uTempOutLen;
	
ERR:
	if (*ppOut == NULL)
		SFree(pTempOut);
	if (pRsa != NULL)
		RSA_free(pRsa);
	
	return err;
}



/**
 * ############################################################################
 * TlsCrRSAVerify
 * ##############
 * @ DESCRIPTION
 *		This function is for the RSA Verify Operation.(RSA Public Decryption)
 * ============================================================================
 * @ INPUT
 *		CrINT8*				pHash
 *			: Pointer to the MD5 or SHA1 or MD5+SHA1 Hashed Value.
 *		CrINT16				uHashLen
 *			: Byte length of the MD5 or SHA1 or MD5+SHA1 Hashed Value.
 *		CrUINT8*			pSignedValue
 *			: Pointer to the RSA Signed Value.
 *		CrUINT16			uSignedValue
 *			: Byte length of the RSA Signed Value.
 *		TLSRSAPrivateKey*	pRSAPrKey
 *			: Pointer to the TLS RSA Private Key Structure.
 * ============================================================================
 * @ OUTPUT
 * ============================================================================
 * @ RETURN
 *		SUCCESS				: noError
 *		FAILURE				: eRSAWrongSignatureLength
 *							  eNoMoreMemory
 *							  eRSAVerifyFailure
 *							  eRSAVerifyinSSL
 * ============================================================================
 * @ HISTORY
 *
 * ############################################################################
 */

TLSCrResult
TlsCrRSAVerify(
	CrUINT8*				pHash,
	CrUINT32				uHashLen,		//16, 20, 36
	CrUINT8*				pSignedValue,
	CrUINT32				uSignedValueLen,
	TLSRSAPublicKey*		pRSAPuKey
)
{
	TLSCrResult				err					= noError;
	CrUINT8*				pTempDecryptedValue = NULL;
	CrINT32					uTempOutLen;
	CrINT32					uTempDecryptedValueLen;
	CrUINT8*				aDigestInfo			= NULL;
	CrINT32					uDigestInfoLen;
	RSA*					pTempRSA			= NULL;

	// Convert TLS RSA Public Key to SSLeay RSA Key
	err = TlsCrRSAPublicTls2SSLeay(&pTempRSA, pRSAPuKey);
	CHECK_ERROR(err);

	if (uSignedValueLen != (CrUINT32)RSA_size(pTempRSA))
		return eRSAWrongSignatureLength;
	
	uTempDecryptedValueLen = SIZE_MAX_RSA_DECRYPT;

	err = SPtrMalloc((void **)&pTempDecryptedValue, uTempDecryptedValueLen);
	CHECK_ERROR(err);

	// SUCCESS : (Hash Size) in WTLS or (Hash Size + sizeof(aDIGEST_INFO_SHA)) in SSL
	// Verifying the Certificate in SSL, 
	// FAILURE : -1 = eSSLeayErrN1
	uTempOutLen = RSA_public_decrypt(	(CrINT32)uSignedValueLen, pSignedValue, 
										pTempDecryptedValue, 
										pTempRSA, RSA_PKCS1_PADDING);
	// In SSL
	if (uTempOutLen <= 0)
	{
		err = -1;
		goto ERR;
	}
	
	switch(uTempOutLen)
	{
	// in SSL
	case SIZE_RSA_DECRYPT_WITH_MD_IN_SSL: // 18 + 16
		// MD5, MD2의 경우에 14번째 byte가 서로 다른다.
		if (*(pTempDecryptedValue+13) == 0x05)
		{
			aDigestInfo = aDIGEST_INFO_MD5;
			uDigestInfoLen = sizeof(aDIGEST_INFO_MD5);
			break;
		}
		else if(*(pTempDecryptedValue+13) == 0x02)
		{
			aDigestInfo = aDIGEST_INFO_MD2;
			uDigestInfoLen = sizeof(aDIGEST_INFO_MD2);
			break;
		}
		else
		{
			err = eRSAVerifyFailure;
			goto ERR;
		}
	case SIZE_RSA_DECRYPT_WITH_SHA1_IN_SSL:
		aDigestInfo = aDIGEST_INFO_SHA;
		uDigestInfoLen = sizeof(aDIGEST_INFO_SHA);
		break;
	// in WTLS
	default:
		aDigestInfo = NULL;
		uDigestInfoLen = 0;
	}

	if (aDigestInfo != NULL)
	{
		if (SMemcmp(pTempDecryptedValue, aDigestInfo, uDigestInfoLen) != 0)
		{
			err = eRSAVerifyinSSL;
			goto ERR;
		}
	}

	if (SMemcmp(pTempDecryptedValue+uDigestInfoLen, pHash, uHashLen) != 0)
	{
		err = eRSAVerifyFailure;
		goto ERR;
	}

	err = noError;


ERR:
	SClearFree((void**)&pTempDecryptedValue, uTempDecryptedValueLen);
	RSA_free(pTempRSA);

	return err;
}



#endif	//#ifdef TLS_API_RSA
