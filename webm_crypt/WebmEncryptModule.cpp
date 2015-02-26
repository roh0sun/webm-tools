#include "stdafx.h"

#include "WebmEncryptModule.h"
#include "webm_endian.h"

using std::string;
using CryptoPP::Exception;
using CryptoPP::AES;
using CryptoPP::CTR_Mode;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

using namespace webm_crypt_dll;

static void GenerateCounterBlock(const std::string& iv, std::string* counter_block)
{
	counter_block->reserve(kKeySize);
	counter_block->append(iv);
	counter_block->append(kKeySize - kIVSize, 0);
}

WebmEncryptModule* WebmEncryptModule::Create(const std::string& secret, uint64_t initial_iv)
{
	return new WebmEncryptModule(secret, initial_iv);
}

void WebmEncryptModule::Destroy(WebmEncryptModule* instance)
{
	delete instance;
}

WebmEncryptModule::WebmEncryptModule(const std::string& secret, uint64_t initial_iv)
	: do_not_encrypt_(false)
	, next_iv_(initial_iv)
	, secret_(secret)
{
}

WebmEncryptModule::~WebmEncryptModule()
{
}

bool WebmEncryptModule::Init()
{
	return true;
}

bool WebmEncryptModule::ProcessData(const uint8_t* plaintext, size_t size, uint8_t* ciphertext, size_t* ciphertext_size)
{
	if (!ciphertext || !ciphertext_size)
	{
		error_message_ = "Invalid pointer";
		return false;
	}

	size_t cipher_temp_size = size + kSignalByteSize;

	if (!do_not_encrypt_)
	{
		const uint64_t iv = next_iv_++;
		const string iv_str(reinterpret_cast<const char*>(&iv), kIVSize);
		
		string counter_block;
		GenerateCounterBlock(iv_str, &counter_block);

		cipher_temp_size += kIVSize;
		if (*ciphertext_size < cipher_temp_size)
		{
			*ciphertext_size = cipher_temp_size;
			error_message_ = "Insufficient memory";
			return false;
		}

		enc_.SetKeyWithIV((const byte*)secret_.data(), secret_.length(),
			(const byte*)counter_block.data(), counter_block.length());

		encrypted_.clear();
		StringSource(plaintext, size, true,
			new StreamTransformationFilter(enc_,
			new StringSink(encrypted_) // StreamTransformationFilter
			)
		);

		memcpy(ciphertext + kSignalByteSize, &iv, kIVSize);
		memcpy(ciphertext + kIVSize + kSignalByteSize, encrypted_.data(), encrypted_.length());
	}
	else
	{
		if (*ciphertext_size < cipher_temp_size)
		{
			*ciphertext_size = cipher_temp_size;
			error_message_ = "Insufficient memory";
			return false;
		}

		memcpy(ciphertext + kSignalByteSize, reinterpret_cast<const char*>(plaintext), size);
	}

	const uint8_t signal_byte = do_not_encrypt_ ? 0 : kEncryptedFrame;
	ciphertext[0] = signal_byte;
	*ciphertext_size = cipher_temp_size;

	error_message_.clear();
	return true;
}

void WebmEncryptModule::set_do_not_encrypt(bool flag)
{
	do_not_encrypt_ = flag;
}

const char* WebmEncryptModule::GetError()
{
	return error_message_.c_str();
}
