#pragma once

#include "WebmCryptCommon.h"

namespace crypto {
	class SymmetricKey;
	class Encryptor;
}

namespace webm_crypt_dll {

	class WebmDecryptModule
	{
	protected:
		WebmDecryptModule(const EncryptionSettings& enc, const std::string& secret);
		~WebmDecryptModule();

	public:
		WECAPI static WebmDecryptModule* Create(const EncryptionSettings& enc, const std::string& secret);
		WECAPI static void Destroy(WebmDecryptModule* instance);
		WECAPI bool Init();
		WECAPI bool DecryptData(const uint8_t* data, size_t length, uint8_t* plaintext, size_t* plaintext_size);
		WECAPI void set_do_not_decrypt(bool flag);
		WECAPI const char* GetError();

	private:
		bool do_not_decrypt_;
		const EncryptionSettings enc_;
		std::unique_ptr<crypto::SymmetricKey> key_;
		std::unique_ptr<crypto::Encryptor> encryptor_;
		std::string error_message_;
		std::string decrypttext_;
	};
}