#include "WebmEncryptModule.h"

#pragma warning(push)
#pragma warning(disable:4127)
#include "base/base_switches.h"
#include "crypto/encryptor.h"
#include "crypto/symmetric_key.h"
#include "webm_endian.h"
#pragma warning(pop)

using crypto::Encryptor;
using crypto::SymmetricKey;
using std::string;
using std::unique_ptr;

bool webm_crypt_dll::GenerateRandomData(size_t length, uint8_t* data)
{
	if (!data)
		return false;

	string temp;
	while (temp.length() < length)
	{
		scoped_ptr<SymmetricKey> key(SymmetricKey::GenerateRandomKey(SymmetricKey::AES, 128));
		string raw_key;
		if (!key->GetRawKey(&raw_key))
		{
			return false;
		}
		temp.append(raw_key);
	}

	memcpy(data, temp.data(), length);
	return true;
}

bool webm_crypt_dll::GenerateRandomUInt64(uint64_t* value)
{
	if (!value)
		return false;

	scoped_ptr<SymmetricKey> key(SymmetricKey::GenerateRandomKey(SymmetricKey::AES, 128));
	string raw_key;
	if (!key->GetRawKey(&raw_key) || raw_key.length() < sizeof(*value))
		return false;
	memcpy(value, raw_key.data(), sizeof(*value));
	return true;
}
