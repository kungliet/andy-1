#include "crypto/CrConfig.h"

#include "crypto/CrSMemMgr.h"
#include "crypto/CrError.h" // for eNoMoreMemory, noError

CrINT16
SPtrMalloc(
	void**	ppMem,
	size_t	uSize
)
{
	*ppMem = SMalloc(uSize);
	if (*ppMem == NULL)
		return eNoMoreMemory;
	else
	{
#ifdef _CLEAR_MALLOC
		SMemset(*ppMem, MEM_CLEAR_CHAR, uSize);
#endif
		return noError;
	}
}


void 
SClearFree(
	void**	ppMem,
	size_t	uSize
)
{
	if (*ppMem == NULL)
		return;

	SMemset(*ppMem, MEM_CLEAR_CHAR, uSize);
	SFree(*ppMem);
	*ppMem = NULL;
}

