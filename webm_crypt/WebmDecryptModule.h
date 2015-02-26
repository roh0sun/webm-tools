#pragma once

#include "WebmCryptCommon.h"

#include <string>

#pragma warning(push)
#pragma warning(disable:4512 4100 4244 4100 4189 4127 4505)
#include "cryptlib.h"
#include "aes.h"
#include "ccm.h"
#include "filters.h"
#pragma warning(pop)

namespace webm_crypt_dll {

class WebmDecryptModule
{
protected:
	WebmDecryptModule(const std::string& secret);
	~WebmDecryptModule();

public:
	WECAPI static WebmDecryptModule* Create(const std::string& secret);
	WECAPI static void Destroy(WebmDecryptModule* instance);
	WECAPI bool Init();
	WECAPI bool ProcessData(const uint8_t* data, size_t length, uint8_t* plaintext, size_t* plaintext_size);
	WECAPI void set_do_not_decrypt(bool flag);
	WECAPI const char* GetError();

private:
	bool do_not_decrypt_;
	std::string base_secret_file_;
	std::string error_message_;
	std::string secret_;
	std::string decrypted_;
	CryptoPP::CTR_Mode< CryptoPP::AES >::Decryption dec_;
};

}