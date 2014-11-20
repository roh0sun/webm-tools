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

	// Struct to hold encryption settings for a single WebM stream.
	struct EncryptionSettings {
		EncryptionSettings()
			: base_secret_file()
			, cipher_mode("CTR")
			, content_id()
			, initial_iv(0)
			, unencrypted_range(0) {
		}

		// Path to a file which holds the base secret.
		std::string base_secret_file;

		// AES encryption algorithm. Currently only "CTR" is supported.
		std::string cipher_mode;

		// WebM Content ID element.
		std::string content_id;

		// Initial Initialization Vector for encryption.
		uint64_t initial_iv;

		// Do not encrypt frames that have a start time less than
		// |unencrypted_range| in milliseconds.
		int64_t unencrypted_range;
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