#pragma once

#include <stdint.h>
#include <string>
#include <memory>

#ifndef WECAPI
#  ifdef WEBM_CRYPT_DLL_BUILD
#    define WECAPI __declspec(dllexport)
#  else
#    define WECAPI __declspec(dllimport)
#  endif
#endif

namespace webm_crypt_dll {

	struct EncryptionSettings {
		EncryptionSettings()
			: cipher_mode("CTR")
			, content_id()
			, initial_iv(0) {
		}

		std::string base_secret_file;
		std::string cipher_mode;
		std::string content_id;
		uint64_t initial_iv;
	};

	static const size_t kDefaultContentIDSize = 16;
	static const size_t kIVSize = 8;
	static const size_t kKeySize = 16;
	static const size_t kSHA1DigestSize = 20;
	static const size_t kSignalByteSize = 1;
	static const uint8_t kEncryptedFrame = 0x1;

	WECAPI bool GenerateRandomData(size_t length, uint8_t* data);
	WECAPI bool GenerateRandomUInt64(uint64_t* value);
}