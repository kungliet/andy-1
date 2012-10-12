#include "crypto/TlsCrConfig.h"
#ifdef TLS_API_RSA


#include "crypto/TlsCrKeySt.h"
#include "crypto/TlsCrMemMgr.h"
#include "crypto/TlsCrRSAMem.h"




void
TlsCrFreeRSAPublicKey
(
	TLSRSAPublicKey**	ppRSAPuKey
)
{
	TLSRSAPublicKey*	pRSAPuKey;

	if ( (ppRSAPuKey == NULL) || (*ppRSAPuKey == NULL) )
		return;

	pRSAPuKey = *ppRSAPuKey;
	TlsFreeMemory((void **)&pRSAPuKey->pExponent, pRSAPuKey->exponentSize);
	TlsFreeMemory((void **)&pRSAPuKey->pModulus, pRSAPuKey->modulusSize);
	TlsFreeMemory((void **)ppRSAPuKey, sizeof(TLSRSAPublicKey));

	*ppRSAPuKey = NULL;

	return;
}

void
TlsCrFreeRSAPrivateKey
(
	TLSRSAPrivateKey**		ppRSAPrKey
)
{
	TLSRSAPrivateKey*		pRSAPrKey;

	if ( (ppRSAPrKey == NULL) || (*ppRSAPrKey == NULL ) )
		return;

	pRSAPrKey = *ppRSAPrKey;

	TlsFreeMemory((void **)&pRSAPrKey->pModulus, pRSAPrKey->modulusSize);
	TlsFreeMemory((void **)&pRSAPrKey->pPublicExponent, pRSAPrKey->publicExponentSize);
	TlsFreeMemory((void **)&pRSAPrKey->pPrivateExponent, pRSAPrKey->privateExponentSize);
	TlsFreeMemory((void **)&pRSAPrKey->pPrime1, pRSAPrKey->prime1Size);
	TlsFreeMemory((void **)&pRSAPrKey->pPrime2, pRSAPrKey->prime2Size);
	TlsFreeMemory((void **)&pRSAPrKey->pExponent1, pRSAPrKey->exponent1Size);
	TlsFreeMemory((void **)&pRSAPrKey->pExponent2, pRSAPrKey->exponent2Size);
	TlsFreeMemory((void **)&pRSAPrKey->pCoefficient, pRSAPrKey->coefficientSize);

	TlsFreeMemory((void **)ppRSAPrKey, sizeof(TLSRSAPrivateKey));

	*ppRSAPrKey = NULL;

	return;
}


#endif // end of #ifdef TLS_API_RSA
