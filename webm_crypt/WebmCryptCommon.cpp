#include "stdafx.h"
#include <Wincrypt.h>

#include "WebmEncryptModule.h"
#include "webm_endian.h"

using std::string;
using std::unique_ptr;

static HCRYPTPROV AquireAESCrypto()
{
	HCRYPTPROV hCryptProv(NULL);
	BOOL ret = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	if (!ret)
	{
		DWORD dwResult = GetLastError();
		if (dwResult == NTE_BAD_KEYSET)
		{
			ret = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET);
		}
	}
	
	if (ret)
	{
		ret = CryptContextAddRef(hCryptProv, NULL, 0);
		if (!ret)
		{
			hCryptProv = NULL;
		}
	}

	return hCryptProv;
}

static void ReleaseAESCrypto(HCRYPTPROV prov)
{
	CryptReleaseContext(prov, 0);
}

bool webm_crypt_dll::GenerateRandomData(size_t length, uint8_t* data)
{
	if (!data)
		return false;

	BOOL ret = FALSE;
	HCRYPTPROV hCryptProv = AquireAESCrypto();
	if (hCryptProv)
	{
		ret = CryptGenRandom(hCryptProv, length, data);

		ReleaseAESCrypto(hCryptProv);
	}

	return (ret != FALSE);
}

bool webm_crypt_dll::GenerateRandomUInt64(uint64_t* value)
{
	if (!value)
		return false;

	BOOL ret = FALSE;
	HCRYPTPROV hCryptProv = AquireAESCrypto();
	if (hCryptProv)
	{
		ret = CryptGenRandom(hCryptProv, sizeof(uint64_t), (BYTE*)value);

		ReleaseAESCrypto(hCryptProv);
	}

	return (ret != FALSE);
}
