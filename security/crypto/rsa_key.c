#include "crypto/rsa_key.h"
#include "crypto/TlsCrError.h"
#ifdef TOOL
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#endif
#if __XEN__
#include "xen/lib.h"
#include "xen/string.h"
#endif


#define MEMCPY_SER(dest, src, length)	\
		memcpy(dest, src, length);	\
		dest = ((char*)dest)+(length);

#define MEMCPY_DESER(dest, src, length)	\
		memcpy(dest, src, length);	\
		src = ((char*)src)+(length);

#define CHECK_LOCAL(err, msg)	\
		if (err != noError)	\
		{	\
			printf("%s\n", msg);	\
			return 1;	\
		}

#ifdef __XEN__
#undef malloc
#define malloc xmalloc_bytes
#undef free
#define free xfree
#endif

/**
 *  *
 *  returned data should be freed
 *  [input]
 *  @param key RSA private key to serialize
 *  [output]
 *  @param buf serialized buf
 *  @param len serialized data length
 *  */
void serialize_pr_key(const TLSRSAPrivateKey* key, unsigned char** buf, int* len)
{
	unsigned char* dest;
	*len = sizeof(TLSModulusSizeType)
				+ sizeof(CrUINT8) * key->modulusSize
				+ sizeof(TLSPublicExponentSizeType)
				+ sizeof(CrUINT8) * key->publicExponentSize
				+ sizeof(TLSPrivateExponentSizeType)
				+ sizeof(CrUINT8) * key->privateExponentSize
				+ sizeof(TLSPrime1SizeType)
				+ sizeof(CrUINT8) * key->prime1Size
				+ sizeof(TLSPrime2SizeType)
				+ sizeof(CrUINT8) * key->prime2Size
				+ sizeof(TLSExponent1SizeType)
				+ sizeof(CrUINT8) * key->exponent1Size
				+ sizeof(TLSExponent2SizeType)
				+ sizeof(CrUINT8) * key->exponent2Size
				+ sizeof(TLSCoefficientSizeType)
				+ sizeof(CrUINT8) * key->coefficientSize;
	dest = (unsigned char*)malloc(*len);
#undef TlsCrRSASign_32
#define TlsCrRSASign_32 TlsCrRSASign
#define TlsCrRSAVerify_32 TlsCrRSAVerify
#define TlsCrSHA1_32 TlsCrSHA1
	if (dest == NULL)
	{
		printf("Allocating memory is failed\n");
		return;
	}
	
	*buf = dest;
	
	MEMCPY_SER(dest, &key->modulusSize, sizeof(TLSModulusSizeType));
	MEMCPY_SER(dest, key->pModulus, sizeof(CrUINT8) * key->modulusSize);

	MEMCPY_SER(dest, &key->publicExponentSize, sizeof(TLSPublicExponentSizeType));
	MEMCPY_SER(dest, key->pPublicExponent, sizeof(CrUINT8) * key->publicExponentSize);

	MEMCPY_SER(dest, &key->privateExponentSize, sizeof(TLSPrivateExponentSizeType));
	MEMCPY_SER(dest, key->pPrivateExponent, sizeof(CrUINT8) * key->privateExponentSize);

	MEMCPY_SER(dest, &key->prime1Size, sizeof(TLSPrime1SizeType));
	MEMCPY_SER(dest, key->pPrime1, sizeof(CrUINT8) * key->prime1Size);

	MEMCPY_SER(dest, &key->prime2Size, sizeof(TLSPrime2SizeType));
	MEMCPY_SER(dest, key->pPrime2, sizeof(CrUINT8) * key->prime2Size);

	MEMCPY_SER(dest, &key->exponent1Size, sizeof(TLSExponent1SizeType));
	MEMCPY_SER(dest, key->pExponent1, sizeof(CrUINT8) * key->exponent1Size);

	MEMCPY_SER(dest, &key->exponent2Size, sizeof(TLSExponent2SizeType));
	MEMCPY_SER(dest, key->pExponent2, sizeof(CrUINT8) * key->exponent2Size);

	MEMCPY_SER(dest, &key->coefficientSize, sizeof(TLSCoefficientSizeType));
	MEMCPY_SER(dest, key->pCoefficient, sizeof(CrUINT8) * key->coefficientSize);
}

/**
 *  *
 *  [input]
 *  @param src serialized data
 *  [output]
 *  @param key RSA private key to deserialize
 *  */
void deserialize_pr_key(TLSRSAPrivateKey* key, const unsigned char* src)
{
	const unsigned char* ptr = src;
	MEMCPY_DESER(&key->modulusSize, ptr, sizeof(TLSModulusSizeType));
	key->pModulus = (unsigned char*)malloc(sizeof(CrUINT8) * key->modulusSize);
	MEMCPY_DESER(key->pModulus, ptr, sizeof(CrUINT8) * key->modulusSize);

	MEMCPY_DESER(&key->publicExponentSize, ptr, sizeof(TLSPublicExponentSizeType));
	key->pPublicExponent = (unsigned char*)malloc(sizeof(CrUINT8) * key->publicExponentSize);
	MEMCPY_DESER(key->pPublicExponent, ptr, sizeof(CrUINT8) * key->publicExponentSize);

	MEMCPY_DESER(&key->privateExponentSize, ptr, sizeof(TLSPrivateExponentSizeType));
	key->pPrivateExponent = (unsigned char*)malloc(sizeof(CrUINT8) * key->privateExponentSize);
	MEMCPY_DESER(key->pPrivateExponent, ptr, sizeof(CrUINT8) * key->privateExponentSize);

	MEMCPY_DESER(&key->prime1Size, ptr, sizeof(TLSPrime1SizeType));
	key->pPrime1 = (unsigned char*)malloc(sizeof(CrUINT8) * key->prime1Size);
	MEMCPY_DESER(key->pPrime1, ptr, sizeof(CrUINT8) * key->prime1Size);

	MEMCPY_DESER(&key->prime2Size, ptr, sizeof(TLSPrime2SizeType));
	key->pPrime2 = (unsigned char*)malloc(sizeof(CrUINT8) * key->prime2Size);
	MEMCPY_DESER(key->pPrime2, ptr, sizeof(CrUINT8) * key->prime2Size);

	MEMCPY_DESER(&key->exponent1Size, ptr, sizeof(TLSExponent1SizeType));
	key->pExponent1 = (unsigned char*)malloc(sizeof(CrUINT8) * key->exponent1Size);
	MEMCPY_DESER(key->pExponent1, ptr, sizeof(CrUINT8) * key->exponent1Size);

	MEMCPY_DESER(&key->exponent2Size, ptr, sizeof(TLSExponent2SizeType));
	key->pExponent2 = (unsigned char*)malloc(sizeof(CrUINT8) * key->exponent2Size);
	MEMCPY_DESER(key->pExponent2, ptr, sizeof(CrUINT8) * key->exponent2Size);

	MEMCPY_DESER(&key->coefficientSize, ptr, sizeof(TLSCoefficientSizeType));
	key->pCoefficient = (unsigned char*)malloc(sizeof(CrUINT8) * key->coefficientSize);
	MEMCPY_DESER(key->pCoefficient, ptr, sizeof(CrUINT8) * key->coefficientSize);

}


/**
 *  *
 *  returned data should be freed
 *  [input]
 *  @param key RSA public key to serialize
 *  [output]
 *  @param buf serialized buf
 *  @param len serialized data length
 *  */
void serialize_pu_key(const TLSRSAPublicKey* key, unsigned char** buf, int* len)
{
	unsigned char* dest;
	*len = sizeof(TLSExponentSizeType)
				+ sizeof(CrUINT8) * key->exponentSize
				+ sizeof(TLSModulusSizeType)
				+ sizeof(CrUINT8) * key->modulusSize;
	dest = (unsigned char*)malloc(*len);
	if (dest == NULL || key == NULL)
		return;
	*buf = dest;

	MEMCPY_SER(dest, &key->exponentSize, sizeof(TLSExponentSizeType));
	MEMCPY_SER(dest, key->pExponent, sizeof(CrUINT8) * key->exponentSize);

	MEMCPY_SER(dest, &key->modulusSize, sizeof(TLSModulusSizeType));
	MEMCPY_SER(dest, key->pModulus, sizeof(CrUINT8) * key->modulusSize);

}


/**
 *  *
 *  [input]
 *  @param src serialized data
 *  [output]
 *  @param key RSA public key to serialize
 *  */
void deserialize_pu_key(TLSRSAPublicKey* key, const unsigned char* src)
{
	if (key == NULL || src == NULL)
		return;
	MEMCPY_DESER(&key->exponentSize, src, sizeof(TLSExponentSizeType));
	key->pExponent = (unsigned char*)malloc(sizeof(CrUINT8) * key->exponentSize);
	MEMCPY_DESER(key->pExponent, src, sizeof(CrUINT8) * key->exponentSize);

	MEMCPY_DESER(&key->modulusSize, src, sizeof(TLSModulusSizeType));
	key->pModulus = (unsigned char*)malloc(sizeof(CrUINT8) * key->modulusSize);
	MEMCPY_DESER(key->pModulus, src, sizeof(CrUINT8) * key->modulusSize);
}

#if 0
/**
 *  *
 *  generated keys must be freed by TlsCrFreeRSAPublicKey()
 *  and TlsCrFreeRSAPrivateKey()
 *
 *  @param pr_key RSA private key is hold.(out parameter). It must be NULL
 *  @param pr_key RSA public key is hold.(out parameter). It must be NULL
 *  @return 0 if succeed
 *  */
int generate_rsa_keys(TLSRSAPrivateKey** pr_key, TLSRSAPublicKey** pu_key)
{
	return (int)TlsCrGenerateRSAKey(pr_key, pu_key, 1024);
}
#endif
