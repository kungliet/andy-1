#include "crypto/TlsCrConfig.h"


#include "crypto/CrConfig.h"
#include "crypto/CrBN.h"
#include "crypto/CrSwcRand.h"
#include "crypto/CrSMemMgr.h"
#include "crypto/TlsCrKeySt.h"
#include "crypto/TlsCrSecurity.h"
#include "crypto/TlsCrSSLeayLib.h"
#include "crypto/TlsCrError.h"














//SSLeay Big Number to Byte String conversion
TLSCrResult
TlsCrSSLeayBn2Bin(
	CrUINT8**			ppOut,
	CrUINT16*			pOutSize,
	BIGNUM*				pSSLeayBN
)
{
	TLSCrResult		err = noError;
	CrUINT8*		pTempOut = NULL;

		
	//get number of bytes of BIG Number
	*pOutSize = (CrUINT16)BN_num_bytes(pSSLeayBN);

	if (*ppOut == NULL )
	{
		err = SPtrMalloc((void **)&pTempOut, (CrUINT16) (sizeof(CrUINT8) * (*pOutSize)));
		CHECK_ERROR(err);
	}
	else
		pTempOut = *ppOut;

	SMemset(pTempOut, MEM_CLEAR_CHAR, *pOutSize);

	if (!BN_bn2bin(pSSLeayBN, pTempOut) )
	{
		if (*ppOut == NULL)
			SFree(pTempOut);
		return eSSLeayBn2BinFailure ;
	}

	if (*ppOut == NULL )
		*ppOut = pTempOut;

	return noError;
}




#ifdef ISEC_API_SWC_RANDOM_NUMBER

TLSCrResult
TlsCrGenerateRandomNumber(
	CrUINT8**	ppOut,				//out
	CrUINT16	outSize				//in
)
{
	TLSCrResult		err = noError;
	CrUINT8*		pTempOut = NULL;
	


	if ( *ppOut == NULL ) {
		err = SPtrMalloc((void **)&pTempOut, (CrUINT16)(sizeof(CrUINT8) * outSize));
		CHECK_ERROR(err);
	}
	else
		pTempOut = *ppOut;
	

	if (getRandomBytes(pTempOut, outSize))
	{
		if (*ppOut == NULL)
			SFree(pTempOut);
		return eRandomNumberFailure;
	}

	
	if (*ppOut == NULL) 
		*ppOut = pTempOut;

	return noError;

}

#endif // end of #ifdef ISEC_API_SWC_RANDOM_NUMBER
