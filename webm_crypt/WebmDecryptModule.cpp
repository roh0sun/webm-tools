#include "WebmDecryptModule.h"

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

using namespace webm_crypt_dll;

static bool GenerateCounterBlock(const std::string& iv, std::string* counter_block)
{
	if (!counter_block || iv.size() != kIVSize)
		return false;

	counter_block->reserve(kKeySize);
	counter_block->append(iv);
	counter_block->append(kKeySize - kIVSize, 0);

	return true;
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
{
	encryptor_.reset(new Encryptor);
	key_.reset(SymmetricKey::Import(SymmetricKey::AES, secret));
}

WebmDecryptModule::~WebmDecryptModule()
{
}

bool WebmDecryptModule::Init()
{
	if (!key_.get())
	{
		error_message_ = "Error creating encryption key";
		return false;
	}

	if (!do_not_decrypt_)
	{
		if (!encryptor_->Init(key_.get(), Encryptor::CTR, ""))
		{
			error_message_ = "Could not initialize decryptor";
			return false;
		}
	}

	error_message_.clear();
	return true;
}

bool WebmDecryptModule::ProcessData(const uint8* data, size_t length, uint8_t* plaintext, size_t* plaintext_size)
{
	if (!plaintext || !plaintext_size)
	{
		error_message_ = "Invalid pointer";
		return false;
	}

	if (!do_not_decrypt_)
	{
		if (length == 0)
		{
			error_message_ = "Length of encrypted data is 0";
			return false;
		}

		const uint8 signal_byte = data[0];

		if (signal_byte & kEncryptedFrame)
		{
			if (length < kSignalByteSize + kIVSize)
			{
				error_message_ = "Not enough data to read IV";
				return false;
			}

			const char* iv_data = reinterpret_cast<const char*>(data + kSignalByteSize);
			const string iv(iv_data, kIVSize);

			string counter_block;
			if (!GenerateCounterBlock(iv, &counter_block))
			{
				error_message_ = "Could not generate counter block";
				return false;
			}

			if (!encryptor_->SetCounter(counter_block))
			{
				error_message_ = "Could not set counter";
				return false;
			}

			const size_t offset = kSignalByteSize + kIVSize;
			// Skip past the IV.
			const string encryptedtext(reinterpret_cast<const char*>(data + offset), length - offset);
			if (!encryptor_->Decrypt(encryptedtext, &decrypttext_))
			{
				error_message_ = "Could not decrypt data";
				return false;
			}
			*plaintext_size = decrypttext_.length();
			memcpy(plaintext, decrypttext_.data(), decrypttext_.length());
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
