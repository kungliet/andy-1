#include "crypto/TlsCrConfig.h"
#ifdef TLS_API_RSA

#include "crypto/CrConfig.h"
#include "crypto/CrRSA.h"


#include "crypto/TlsCrKeySt.h"
#include "crypto/TlsCrSecurity.h"
#include "crypto/TlsCrSSLeayLib.h"
#include "crypto/TlsCrError.h"

#include "crypto/CrSMemMgr.h"
#include "crypto/TlsCrRSAMem.h"





 /**
 * #########################################################################################
 * TlsCrRSAPublicSSLeay2Tls
 * ########################
 *
 * DESCRIPTION
 *		This function is for the conversion from [SSLeay RSA Structure] to 
 *		[TLS RSA Public Key Structure].
 * =========================================================================================
 * INPUT
 *		RSA*				pRsa		: Pointer of SSLeay RSA Structure.
 * =========================================================================================
 * OUTPUT
 *		TLSRSAPublicKey**	ppRSAPuKey	: Pointer to PointerTLS RSA Public Key Structure.
 * =========================================================================================
 * RETURN
 *		SUCCESS				: noError
 *		FAILURE				: eNoMoreMemory, eSSLeayBn2BinFailure
 * #########################################################################################
 */
TLSCrResult
TlsCrRSAPublicSSLeay2Tls(
	TLSRSAPublicKey**	ppRSAPuKey,
	RSA*				pRsa
)
{
	TLSRSAPublicKey*	pPuKey;
	TLSCrResult			err;


	if (*ppRSAPuKey == NULL )
	{
		err = SPtrMalloc((void **)&pPuKey, sizeof(TLSRSAPublicKey));
		CHECK_ERROR(err);
		pPuKey->pExponent = pPuKey->pModulus = NULL;
	}
	else 
		pPuKey = *ppRSAPuKey;


	err = TlsCrSSLeayBn2Bin(&(pPuKey->pExponent), &(pPuKey->exponentSize), pRsa->e);
	CHECK_LOCAL_ERROR(err);

	err = TlsCrSSLeayBn2Bin(&(pPuKey->pModulus), &(pPuKey->modulusSize), pRsa->n);
	CHECK_LOCAL_ERROR(err);

	if (*ppRSAPuKey == NULL)
		*ppRSAPuKey = pPuKey;

ERR:
	if (*ppRSAPuKey == NULL)
		TlsCrFreeRSAPublicKey(&pPuKey);

	return err;

}

 /**
 * #########################################################################################
 * TlsCrRSAPrivateSSLeay2Tls
 * #########################
 *
 * DESCRIPTION
 *		This function is for the conversion from [TLS RSA Private Key Structure] to 
 *		[SSLeay RSA Structure].
 * =========================================================================================
 * INPUT
 *		RSA*				pRsa		: Pointer of SSLeay RSA Structure.
 * =========================================================================================
 * OUTPUT
 *		TLSRSAPrivateKey**	ppRSAPrKey	: Pointer to PointerTLS RSA Private Key Structure.
 * =========================================================================================
 * RETURN
 *		SUCCESS				: noError
 *		FAILURE				: eNoMoreMemory, eSSLeayBn2BinFailure
 * #########################################################################################
 */
TLSCrResult
TlsCrRSAPrivateSSLeay2Tls(
	TLSRSAPrivateKey** ppRSAPrKey,
	RSA*                pRsa
)
{
    TLSRSAPrivateKey*    pPrKey;
	TLSCrResult err;

	if (*ppRSAPrKey == NULL) 
	{
		err = SPtrMalloc((void **)&pPrKey, sizeof(TLSRSAPrivateKey));
		CHECK_ERROR(err);

		//initialize pointer with zeors
		SMemset(pPrKey, 0x00, sizeof(TLSRSAPrivateKey));
	}
	else
		pPrKey = *ppRSAPrKey;

	err = TlsCrSSLeayBn2Bin(&(pPrKey->pPublicExponent), &(pPrKey->publicExponentSize), pRsa->e);
	CHECK_LOCAL_ERROR(err);

	err = TlsCrSSLeayBn2Bin(&(pPrKey->pModulus), &(pPrKey->modulusSize), pRsa->n);
	CHECK_LOCAL_ERROR(err);

	err = TlsCrSSLeayBn2Bin(&(pPrKey->pPrivateExponent), &(pPrKey->privateExponentSize), pRsa->d);
	CHECK_LOCAL_ERROR(err);

	err = TlsCrSSLeayBn2Bin(&(pPrKey->pPrime1), &(pPrKey->prime1Size), pRsa->p);
	CHECK_LOCAL_ERROR(err);

	err = TlsCrSSLeayBn2Bin(&(pPrKey->pPrime2), &(pPrKey->prime2Size), pRsa->q);
	CHECK_LOCAL_ERROR(err);

	err = TlsCrSSLeayBn2Bin(&(pPrKey->pExponent1), &(pPrKey->exponent1Size), pRsa->dmp1);
	CHECK_LOCAL_ERROR(err);

	err = TlsCrSSLeayBn2Bin(&(pPrKey->pExponent2), &(pPrKey->exponent2Size), pRsa->dmq1);
	CHECK_LOCAL_ERROR(err);

	err = TlsCrSSLeayBn2Bin(&(pPrKey->pCoefficient), &(pPrKey->coefficientSize), pRsa->iqmp);
	CHECK_LOCAL_ERROR(err);

	if (*ppRSAPrKey == NULL)
		*ppRSAPrKey = pPrKey;

	return noError;

ERR:
	if (*ppRSAPrKey == NULL)
		TlsCrFreeRSAPrivateKey(&pPrKey);
	       
    return err;
}



 /*TLS RSA Private Key -> SSLeay RSA
 *assume *ppSSLeayRSA is Null Pointer
 *This function is for the function TlsCrRSASignSHA1
 */
 /**
 *
 * SUCCESS	: noError
 * FAILURE	: eNoMoreMemory
 *			: eRSAPrivateTls2SSLeayFailure
 */
TLSCrResult
TlsCrRSAPrivateTls2SSLeay(
	RSA**				ppSSLeayRsa,
	TLSRSAPrivateKey*	pPrKey)
{

	RSA*	pRsa;
	
	pRsa = RSA_new();
	if (pRsa == NULL)
		return eNoMoreMemory;

	
    pRsa->n=BN_bin2bn(pPrKey->pModulus, pPrKey->modulusSize, NULL);
	if (pRsa->n == NULL)
		goto ERR;
       
	pRsa->e=BN_bin2bn(pPrKey->pPublicExponent, pPrKey->publicExponentSize, NULL);
	if (pRsa->e == NULL)
		goto ERR;
                
    pRsa->d=BN_bin2bn(pPrKey->pPrivateExponent, pPrKey->privateExponentSize, NULL);
	if (pRsa->d == NULL)
		goto ERR;
                
    pRsa->p=BN_bin2bn(pPrKey->pPrime1, pPrKey->prime1Size, NULL);
	if (pRsa->p == NULL)
		goto ERR;
                
    pRsa->q=BN_bin2bn(pPrKey->pPrime2, pPrKey->prime2Size, NULL);
	if (pRsa->q == NULL)
		goto ERR;
                
    pRsa->dmp1=BN_bin2bn(pPrKey->pExponent1, pPrKey->exponent1Size, NULL);
	if (pRsa->dmp1 == NULL)
		goto ERR;
                
    pRsa->dmq1=BN_bin2bn(pPrKey->pExponent2, pPrKey->exponent2Size, NULL);
	if (pRsa->dmp1 == NULL)
		goto ERR;
                
    pRsa->iqmp=BN_bin2bn(pPrKey->pCoefficient, pPrKey->coefficientSize, NULL);
	if (pRsa->iqmp == NULL)
		goto ERR;

	*ppSSLeayRsa = pRsa;
	return noError;

ERR:
	RSA_free(pRsa);
	return eRSAPrivateTls2SSLeayFailure;
	
}

 /**
 * ######################################################################
 * TlsCrRSAPublicTls2SSLeay
 * =============
 *		Description : Convert TLS RSA Public Key to SSLeay RSA Key.
 *
 *		INPUT
 *			TLSRSAPublicKey*	pPuKey				: TLS RSA Public Key
 *
 *		OUTPUT
 *			RSA**				ppSSLeayRsa,		: SSLeay RSA Key
 *
 *		RETURN
 *			SUCCESS				: noError
 *			FAILURE				: eRSAPublicTls2SSLeayFailure
 *								  eNoMoreMemory
 * ######################################################################
 */
TLSCrResult
TlsCrRSAPublicTls2SSLeay(
	RSA**				ppSSLeayRsa,
	TLSRSAPublicKey*	pPuKey)
{
	RSA*	pRsa;

	pRsa = RSA_new();
	if (pRsa == NULL)
		return eNoMoreMemory;

	
	pRsa->n = BN_bin2bn(pPuKey->pModulus, pPuKey->modulusSize, NULL);
	if (pRsa->n ==  NULL)
		goto ERR;

	pRsa->e = BN_bin2bn(pPuKey->pExponent, pPuKey->exponentSize, NULL);
	if (pRsa->e == NULL)
		goto ERR;
	
	*ppSSLeayRsa = pRsa;
	return noError;

ERR:
	RSA_free(pRsa);
	return eRSAPublicTls2SSLeayFailure;

}








#endif // end of #ifdef TLS_API_RSA

