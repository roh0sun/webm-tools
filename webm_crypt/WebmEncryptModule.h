#pragma once

#include "WebmCryptCommon.h"

namespace crypto {
	class SymmetricKey;
}

namespace webm_crypt_dll {

	class WebmEncryptModule
	{
	protected:
		WebmEncryptModule(const EncryptionSettings& enc, const std::string& secret);
		~WebmEncryptModule();

	public:
		WECAPI static WebmEncryptModule* Create(const EncryptionSettings& enc, const std::string& secret);
		WECAPI static void Destroy(WebmEncryptModule* instance);
		WECAPI bool Init();
		WECAPI bool ProcessData(const uint8_t* plaintext, size_t size, uint8_t* ciphertext, size_t* ciphertext_size);
		WECAPI void set_do_not_encrypt(bool flag);
		WECAPI const char* GetError();

	private:
		bool do_not_encrypt_;
		const EncryptionSettings enc_;
		std::unique_ptr<crypto::SymmetricKey> key_;
		uint64_t next_iv_;
		std::string error_message_;
	};
}