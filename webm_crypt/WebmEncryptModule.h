#pragma once

#include "WebmCryptCommon.h"

#pragma warning(push)
#pragma warning(disable:4512 4100 4244 4100 4189 4127 4505)
#include "cryptlib.h"
#include "aes.h"
#include "ccm.h"
#include "filters.h"
#pragma warning(pop)

namespace webm_crypt_dll {

class WebmEncryptModule
{
protected:
	WebmEncryptModule(const std::string& secret, uint64_t initial_iv);
	~WebmEncryptModule();

public:
	WECAPI static WebmEncryptModule* Create(const std::string& secret, uint64_t initial_iv);
	WECAPI static void Destroy(WebmEncryptModule* instance);
	WECAPI bool Init();
	WECAPI bool ProcessData(const uint8_t* plaintext, size_t size, uint8_t* ciphertext, size_t* ciphertext_size);
	WECAPI void set_do_not_encrypt(bool flag);
	WECAPI const char* GetError();

private:
	bool do_not_encrypt_;
	uint64_t next_iv_;
	std::string error_message_;
	std::string secret_;
	std::string encrypted_;
	CryptoPP::CTR_Mode< CryptoPP::AES >::Encryption enc_;
};

}