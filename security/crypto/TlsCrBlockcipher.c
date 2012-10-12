/**
 * ############################################################################
 *
 * ############################################################################
 */

#include "crypto/TlsCrConfig.h"
#ifdef TLS_API_SYMMETRIC_CIPHER

#include "crypto/CrConfig.h"
#include "crypto/CrEvp.h"
#include "crypto/CrSMemMgr.h"
#include "crypto/CrAESApi.h"
#include "crypto/TlsCrSecurity.h"
#include "crypto/TlsCrKeySt.h"
#include "crypto/TlsCrBlockCipher.h"
#include "crypto/TlsCrMemMgr.h"
#include "crypto/TlsCrError.h"



#define BLOCK_ENC		1
#define BLOCK_DEC		0

#define SSLEAY_NO_ERR	1

#define B_BLOCK_SIZE	8 // block cipher's block size
#define S_BLOCK_SIZE	1



static TLSCrResult 
CIPHERNum2CIPHER(
	EVP_CIPHER**			ppEncryptionAlgorithm,
	TLSBulkCipherAlgorithm	iBulkCipherIndex
);




 /**
 * TlsCrEncryptBlock
 */

TLSCrResult 
TlsCrEncryptBlock_32(
	CrUINT8**				ppOut,				//out
	CrUINT32*				pOutLen,				//out
	CrUINT8*				pData,				//in
	CrUINT32				uDataLen,			//in
	CrUINT8*				pKey,				//in
	CrUINT32				uKeyLen,				//in
	CrUINT8*				pIV,				//in
	CrUINT32				uIVLen,				//in
	TLSBulkCipherAlgorithm	iBulkCipherIndex	//in
)
{
	EVP_CIPHER_CTX		cipher_ctx;
	EVP_CIPHER*			pEncryptionAlgorithm = NULL;

	CrUINT8*			pTempOut = NULL;
	CrUINT32			uTempOutLen1;
	CrUINT32			uTempOutLen2;
	CrUINT32			lastPartLen;
	TLSCrResult			err ;

	//encryption algorithm check
	err = CIPHERNum2CIPHER(&pEncryptionAlgorithm, iBulkCipherIndex);
	CHECK_LOCAL_ERROR(err);
	
	EVP_CipherInit(&cipher_ctx, pEncryptionAlgorithm, pKey, pIV, BLOCK_ENC);

	if (*ppOut == NULL)
	{
		uTempOutLen2 = cipher_ctx.cipher->block_size;
		uTempOutLen1 = (CrUINT32)((uDataLen+uTempOutLen2)/uTempOutLen2*uTempOutLen2);
		err = SPtrMalloc((void **)&pTempOut, uTempOutLen1);
		CHECK_LOCAL_ERROR(err);
		
	}
	else {
		pTempOut = *ppOut;
		uTempOutLen1 = *pOutLen;
	}

	EVP_CipherUpdate(&cipher_ctx, pTempOut, (CrINT32 *)&uTempOutLen1, pData, (CrINT32)(uDataLen));	
	EVP_CipherFinal(&cipher_ctx, pTempOut+uTempOutLen1, &lastPartLen);

	if (*ppOut == NULL) 
		*ppOut = pTempOut;
	*pOutLen = uTempOutLen1+lastPartLen;
	
	return err;

ERR:
	if (*ppOut == NULL)
		SFree(pTempOut);
	
	return (err);
}


TLSCrResult 
TlsCrEncryptBlock(
	CrUINT8**				ppOut,				//out
	CrUINT16*				pOutLen,				//out
	CrUINT8*				pData,				//in
	CrUINT16				uDataLen,			//in
	CrUINT8*				pKey,				//in
	CrUINT16				uKeyLen,				//in
	CrUINT8*				pIV,				//in
	CrUINT16				uIVLen,				//in
	TLSBulkCipherAlgorithm	iBulkCipherIndex	//in
)
{
	EVP_CIPHER_CTX		cipher_ctx;
	EVP_CIPHER*			pEncryptionAlgorithm = NULL;

	CrUINT8*			pTempOut = NULL;
	CrUINT32			uTempOutLen1;
	CrUINT16			uTempOutLen2;
//	CrUINT16			lastPartLen;
/* Corrected from CrUINT16 to 32 */
/* Sung-Min */
	CrUINT32			lastPartLen;

	TLSCrResult			err ;

	


	//encryption algorithm check
	err = CIPHERNum2CIPHER(&pEncryptionAlgorithm, iBulkCipherIndex);
	CHECK_LOCAL_ERROR(err);
	
	EVP_CipherInit(&cipher_ctx, pEncryptionAlgorithm, pKey, pIV, BLOCK_ENC);


	if (*ppOut == NULL)
	{
		uTempOutLen2 = cipher_ctx.cipher->block_size;
		uTempOutLen1 = (CrUINT32)((uDataLen+uTempOutLen2)/uTempOutLen2*uTempOutLen2);
		err = SPtrMalloc((void **)&pTempOut, uTempOutLen1);
		CHECK_LOCAL_ERROR(err);
		
	}
	else {
		pTempOut = *ppOut;
		uTempOutLen1 = *pOutLen;
	}


	EVP_CipherUpdate(&cipher_ctx, pTempOut, (CrINT32 *)&uTempOutLen1, pData, (CrINT32)(uDataLen));	



	EVP_CipherFinal(&cipher_ctx, pTempOut+uTempOutLen1, &lastPartLen);


	if (*ppOut == NULL) 
		*ppOut = pTempOut;
	*pOutLen = uTempOutLen1+lastPartLen;
	
	return err;

ERR:
	if (*ppOut == NULL)
		SFree(pTempOut);
	
	return (err);
}



TLSCrResult 
TlsCrDecryptBlock_32(
	CrUINT8**				ppOut,	//out
	CrUINT32*				pOutLen,
	CrUINT8*				pData,	//in
	CrUINT32				uDataLen,
	CrUINT8*				pKey,	//in
	CrUINT32				uKeyLen,
	CrUINT8*				pIV,	//in
	CrUINT32				uIVLen,
	TLSBulkCipherAlgorithm	iBulkCipherIndex	// in
)
{
	EVP_CIPHER_CTX	cipher_ctx;
	EVP_CIPHER*		pEncryptionAlgorithm;
	CrINT32			lastPartLen;
	CrUINT8*		pTempOut = NULL;
	CrUINT32		uTempOutLen;

	TLSCrResult		err ;


	if (uIVLen % 8 !=0 )
		return eLengthMismatch;
 
	if (*ppOut == NULL)
	{
		uTempOutLen = (CrUINT32)uDataLen;
		err = SPtrMalloc((void **)&pTempOut, uTempOutLen);
		CHECK_ERROR(err);
	}
	else
	{
		pTempOut = *ppOut;
		uTempOutLen = *pOutLen;
	}

	//encryption algorithm check
	err = CIPHERNum2CIPHER(&pEncryptionAlgorithm, iBulkCipherIndex);
	CHECK_LOCAL_ERROR(err);

	EVP_CipherInit(&cipher_ctx, pEncryptionAlgorithm, pKey, pIV, BLOCK_DEC);

	EVP_CipherUpdate(&cipher_ctx, pTempOut, (CrINT32 *)&uTempOutLen, pData, (CrINT32)uDataLen);
	//for last block 


	EVP_CipherFinal(&cipher_ctx, pTempOut+uTempOutLen, &lastPartLen);

	if (*ppOut == NULL)
		*ppOut = pTempOut;
	*pOutLen = uTempOutLen+(CrUINT32)lastPartLen;
	
	return err;

ERR:
	if (*ppOut == NULL)
		SFree(pTempOut);

	return (err);
}



TLSCrResult 
TlsCrDecryptBlock(
	CrUINT8**				ppOut,	//out
	CrUINT16*				pOutLen,
	CrUINT8*				pData,	//in
	CrUINT16				uDataLen,
	CrUINT8*				pKey,	//in
	CrUINT16				uKeyLen,
	CrUINT8*				pIV,	//in
	CrUINT16				uIVLen,
	TLSBulkCipherAlgorithm	iBulkCipherIndex	// in
)
{
	EVP_CIPHER_CTX	cipher_ctx;
	EVP_CIPHER*		pEncryptionAlgorithm;
	CrINT32			lastPartLen;
	CrUINT8*		pTempOut = NULL;
	CrUINT32		uTempOutLen;

	TLSCrResult		err ;


	if (uIVLen % 8 !=0 )
		return eLengthMismatch;
 
	if (*ppOut == NULL)
	{
		uTempOutLen = (CrUINT32)uDataLen;
		err = SPtrMalloc((void **)&pTempOut, uTempOutLen);
		CHECK_ERROR(err);
	}
	else
	{
		pTempOut = *ppOut;
		uTempOutLen = *pOutLen;
	}

	//encryption algorithm check
	err = CIPHERNum2CIPHER(&pEncryptionAlgorithm, iBulkCipherIndex);
	CHECK_LOCAL_ERROR(err);

	EVP_CipherInit(&cipher_ctx, pEncryptionAlgorithm, pKey, pIV, BLOCK_DEC);

	EVP_CipherUpdate(&cipher_ctx, pTempOut, (CrINT32 *)&uTempOutLen, pData, (CrINT32)uDataLen);
	//for last block 


	EVP_CipherFinal(&cipher_ctx, pTempOut+uTempOutLen, &lastPartLen);

	if (*ppOut == NULL)
		*ppOut = pTempOut;
	*pOutLen = uTempOutLen+(CrUINT32)lastPartLen;
	
	return err;

ERR:
	if (*ppOut == NULL)
		SFree(pTempOut);

	return (err);
}



 /**
 *	###########################################################################
 *								EVP Init
 *	###########################################################################
 *		
 *		
 *		
 *	###########################################################################
 */
TLSCrResult
TlsCrEvpInit (
	EVP_CIPHER_CTX**	ppCipherCtx,	// update와 final에서 필요한 구조체
	CrUINT8*			pKey,		// key
	CrUINT16			uKeyLen,	// key size
	CrUINT8*			pIV,		// initial vector
	CrUINT16			uIVLen,		// initial vector size
	CrINT32				enc,		// enc/dec
	TLSBulkCipherAlgorithm	iBCIdx	// algorithm index
)
{
	EVP_CIPHER_CTX*	pTempCipherCtx;
	EVP_CIPHER*		pEncAlgo;
	TLSCrResult		err=noError;
	
	if (*ppCipherCtx == NULL)
	{
		pTempCipherCtx = (EVP_CIPHER_CTX *)SMalloc(sizeof(EVP_CIPHER_CTX));
		if (pTempCipherCtx == NULL)
			err = eNoMoreMemory;
		CHECK_ERROR(err);
	}
	else
		pTempCipherCtx = *ppCipherCtx;
	
	err = CIPHERNum2CIPHER(&pEncAlgo, iBCIdx);
	CHECK_LOCAL_ERROR(err);
	
	EVP_CipherInit(pTempCipherCtx, pEncAlgo, pKey, pIV, enc);
	
	if (*ppCipherCtx == NULL)
		*ppCipherCtx = pTempCipherCtx;
	
	return err;

ERR:
	if (*ppCipherCtx == NULL)
		SFree(pTempCipherCtx);
	
	return err;
}
 /**
 *	###########################################################################
 *								EVP UPDATE
 *	###########################################################################
 *		
 *		
 *		
 *	###########################################################################
 */

TLSCrResult
TlsCrEvpUpdate (
		EVP_CIPHER_CTX *pCipherCtx,		/* 이전의 enc/dec결과와 key값들을 저장해 둔 구조체 */
		CrUINT8 **ppOut,			/* enc/dec 결과 */
		CrUINT32 *pOutLen,		/* enc/dec 결과의 길이 */
		CrUINT8 *pData,			/* enc/dec할려는 데이터 */
		CrUINT32 uDataLen		/* Data의 길이 */
)
{
	CrUINT8*		pTempOut=NULL;
	CrUINT32		uTempOutLen, uTempOutLen1;
	TLSCrResult		err = noError;

	if (pCipherCtx == NULL)		// 분명히 pCipherCtx는 구조체가 잡혀서 내려온다.
		return eBadCipherCtx;

	if (*ppOut == NULL)
	{
		// encrypt시에 wtls & tls는 padding이 되어서 호출되지만 그렇지 않은 경우에는
		// 다음과 같이 padding될 부분에 대한 메모리를 미리 할당해야 한다.
		uTempOutLen1 = pCipherCtx->cipher->block_size;
		if (pCipherCtx->encrypt)
			uTempOutLen = (uDataLen+uTempOutLen1)/uTempOutLen1*uTempOutLen1;
		else
			uTempOutLen = uDataLen;
		err = SPtrMalloc((void**)&pTempOut, uTempOutLen);
		CHECK_ERROR(err);
	}
	else
	{
		pTempOut = *ppOut;
		uTempOutLen = *pOutLen;
	}
	
	EVP_CipherUpdate(pCipherCtx, pTempOut, (CrINT32 *)&uTempOutLen, pData, (CrINT32)uDataLen);
	
	if (*ppOut == NULL)
		*ppOut = pTempOut;
		
	*pOutLen = uTempOutLen;
	
	return err;
}
 /**
 *	###########################################################################
 *								EVP FINAL
 *	###########################################################################
 *		
 *		
 *		
 *	###########################################################################
 */

TLSCrResult
TlsCrEvpFinal (
	EVP_CIPHER_CTX*		pCipherCtx,	// enc에서는 마지막으로 padding후 enc
	CrUINT8**			ppOut,
	CrUINT32*			pOutLen
)
{
	CrUINT8*	pTempOut=NULL;
	CrUINT32	uTempOutLen;
	TLSCrResult	err = noError;
	
	
	if (*ppOut == NULL)
	{
		uTempOutLen = (CrUINT16)(pCipherCtx->cipher->block_size);
		err = SPtrMalloc((void**)&pTempOut, sizeof(CrUINT8)*uTempOutLen);
		CHECK_ERROR(err);
	}
	else
	{
		pTempOut = *ppOut;
		uTempOutLen = *pOutLen;
	}
	
	if (EVP_CipherFinal(pCipherCtx, pTempOut, (CrINT32*)&uTempOutLen) == 0)
		err = eEvpFinalFailure;
	CHECK_LOCAL_ERROR(err);
	
	if (*ppOut == NULL)
		*ppOut = pTempOut;
	
	*pOutLen = uTempOutLen;

	return err;

ERR:
	if (*ppOut == NULL)
		SFree(pTempOut);
	
	return err;
}
	
	
	




static TLSCrResult
CIPHERNum2CIPHER(
	EVP_CIPHER**			ppEncryptionAlgorithm,
	TLSBulkCipherAlgorithm	iBulkCipherIndex)
{  
	switch (iBulkCipherIndex) 
	{

#ifdef TLS_API_DES //2000.11.06 Tae-Sung Kim Added.
		case TLS_BCIPHER_DES_CBC_40:
		case TLS_BCIPHER_DES_CBC:             
			*ppEncryptionAlgorithm = EVP_des_cbc();
			return (noError);
	
			//Triple DES CBC를 위해 첨가된 부분
		case TLS_BCIPHER_3DES_CBC_EDE:   
			*ppEncryptionAlgorithm = EVP_des_ede3_cbc();
			return (noError);
#endif //TLS_API_DES //2000.11.06 Tae-Sung Kim Added.

#ifdef TLS_API_RC4 // added RC4 2001.11.19
		/*	Modified by Tae Sung Kim (2002.08.01)
			40 refers to the amount of entropy being used and not the key length. 40
			bits of entropy is expanded into a 64bit key of which 56 bits is
			effectively used in DES.
			Similarly "40 bit" RC4 is in fact 40bits of entropy expanded into a 128
			bit key which is then used with RC4.
			So EVP cipher algorithm of TLS_BCIPHER_RC4_40 is not EVP_rc4_40() but EVP_rc4().
		*/
		case TLS_BCIPHER_RC4_40:
		case TLS_BCIPHER_RC4:
			*ppEncryptionAlgorithm = EVP_rc4();
			return (noError);
#endif // end of #ifdef TLS_API_RC4

#ifdef TLS_API_RC5 
		case TLS_BCIPHER_RC5_CBC_40: 
		case TLS_BCIPHER_RC5_CBC_56: 
			*ppEncryptionAlgorithm = EVP_rc5_32_12_16_cbc();
			return (noError);
	
		//2000.5.13 KyungIm Jung Added
		case TLS_BCIPHER_RC5_CBC:
			*ppEncryptionAlgorithm = EVP_rc5_32_16_16_cbc();
			return (noError);
#endif

#ifdef TLS_API_IDEA
		case TLS_BCIPHER_IDEA_CBC_40:
		case TLS_BCIPHER_IDEA_CBC_56:
		case TLS_BCIPHER_IDEA_CBC:
			*ppEncryptionAlgorithm = EVP_idea_cbc();
			return noError;
#endif

#ifdef TLS_API_AES //2002.5.14
		case TLS_BCIPHER_AES_ECB_128:
			*ppEncryptionAlgorithm = EVP_aes_ecb_128();
			return (noError);
		case TLS_BCIPHER_AES_ECB_192:
			*ppEncryptionAlgorithm = EVP_aes_ecb_192();
			return (noError);
		case TLS_BCIPHER_AES_ECB_256:
			*ppEncryptionAlgorithm = EVP_aes_ecb_256();
			return (noError);
		case TLS_BCIPHER_AES_CBC_128:
			*ppEncryptionAlgorithm = EVP_aes_cbc_128();
			return (noError);
		case TLS_BCIPHER_AES_CBC_192:
			*ppEncryptionAlgorithm = EVP_aes_cbc_192();
			return (noError);
		case TLS_BCIPHER_AES_CBC_256:
			*ppEncryptionAlgorithm = EVP_aes_cbc_256();
			return (noError);
		case TLS_BCIPHER_AES_CFB1_128:
			*ppEncryptionAlgorithm = EVP_aes_cfb1_128();
			return (noError);
		case TLS_BCIPHER_AES_CFB1_192:
			*ppEncryptionAlgorithm = EVP_aes_cfb1_192();
			return (noError);
		case TLS_BCIPHER_AES_CFB1_256:
			*ppEncryptionAlgorithm = EVP_aes_cfb1_256();
			return (noError);
#endif //2002.5.14

#ifdef TLS_API_SEED
		case TLS_BCIPHER_SEED_ECB:
			*ppEncryptionAlgorithm = EVP_seed_ecb();
			return (noError);
		case TLS_BCIPHER_SEED_CBC:
			*ppEncryptionAlgorithm = EVP_seed_cbc();
			return (noError);
		case TLS_BCIPHER_SEED_CFB:
			*ppEncryptionAlgorithm = EVP_seed_cfb();
			return (noError);
		case TLS_BCIPHER_SEED_OFB:
			*ppEncryptionAlgorithm = EVP_seed_ofb();
			return (noError);
#endif

#ifdef TLS_API_RC2
		case TLS_BCIPHER_RC2_CBC:
		case TLS_BCIPHER_RC2_CBC_40:
			*ppEncryptionAlgorithm = EVP_rc2_cbc();
			return noError;
#endif
		default:
			return eBEncAlg;
	}
			
}

#endif // end of #ifdef TLS_API_SYMMETRIC_CIPHER
