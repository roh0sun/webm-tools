#include "stdafx.h"

#include "WebmDecryptModule.h"
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

WebmDecryptModule* WebmDecryptModule::Create(const std::string& secret)
{
	return new WebmDecryptModule(secret);
}

void WebmDecryptModule::Destroy(WebmDecryptModule* instance)
{
	delete instance;
}

WebmDecryptModule::WebmDecryptModule(const std::string& secret)
	: do_not_decrypt_(false)
	, secret_(secret)
{
}

WebmDecryptModule::~WebmDecryptModule()
{
}

bool WebmDecryptModule::Init()
{
	return true;
}

bool WebmDecryptModule::ProcessData(const uint8_t* data, size_t length, uint8_t* plaintext, size_t* plaintext_size)
{
	if (!plaintext || !plaintext_size)
	{
		error_message_ = "Invalid pointer";
		return false;
	}

	if (length == 0)
	{
		error_message_ = "Length of encrypted data is 0";
		return false;
	}

	const uint8_t signal_byte = data[0];

	if (!do_not_decrypt_ && (signal_byte & kEncryptedFrame))
	{
		if (length < kSignalByteSize + kIVSize)
		{
			error_message_ = "Not enough data to read IV";
			return false;
		}

		const char* iv_data = reinterpret_cast<const char*>(data + kSignalByteSize);
		const string iv(iv_data, kIVSize);

		string counter_block;
		GenerateCounterBlock(iv, &counter_block);

		const size_t offset = kSignalByteSize + kIVSize;
		if (*plaintext_size < length - offset)
		{
			*plaintext_size = length - offset;
			error_message_ = "Insufficient memory";
			return false;
		}

		dec_.SetKeyWithIV((const byte*)secret_.data(), secret_.length(),
			(const byte*)counter_block.data(), counter_block.length());

		decrypted_.clear();
		StringSource(data + offset, length - offset, true,
			new StreamTransformationFilter(dec_,
			new StringSink(decrypted_) // StreamTransformationFilter
			)
			);

		*plaintext_size = length - offset;
		memcpy(plaintext, decrypted_.data(), decrypted_.length());
	}
	else
	{
		const size_t offset = kSignalByteSize;
		if (*plaintext_size < length - offset)
		{
			*plaintext_size = length - offset;
			error_message_ = "Insufficient memory";
			return false;
		}
		*plaintext_size = length - offset;
		memcpy(plaintext, data + offset, length - offset);
	}

	error_message_.clear();
	return true;
}

void WebmDecryptModule::set_do_not_decrypt(bool flag)
{
	do_not_decrypt_ = flag;
}

const char* WebmDecryptModule::GetError()
{
	return error_message_.c_str();
}
