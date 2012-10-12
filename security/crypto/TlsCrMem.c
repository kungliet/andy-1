#include "crypto/TlsCrConfig.h"
#include "crypto/TlsCrMemMgr.h"
#include "crypto/CrSMemMgr.h"


void 
TlsFreeMemory
(
	void**			ppBuffer,
	size_t			size
)
{
	CrUINT8*		pBuffer;

	if ( (ppBuffer == NULL) || (*ppBuffer == NULL) )
		return;

	pBuffer = *ppBuffer;

	SMemset( (CrUINT8*)pBuffer, 0, size);
	SFree(pBuffer);
	
	*ppBuffer = NULL;

	return;
}




