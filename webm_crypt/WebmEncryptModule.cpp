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
{
	key_.reset(SymmetricKey::Import(SymmetricKey::AES, secret));
}

WebmEncryptModule::~WebmEncryptModule()
{
}

bool WebmEncryptModule::Init()
{
	if (!key_.get())
	{
		error_message_ = "Error creating encryption key";
		return false;
	}

	error_message_.clear();
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
		Encryptor encryptor;
		if (!encryptor.Init(key_.get(), Encryptor::CTR, "")) {
			error_message_ = "Could not initialize encryptor";
			return false;
		}

		// Set the IV.
		const uint64 iv = next_iv_++;

		const string iv_str(reinterpret_cast<const char*>(&iv), kIVSize);
		string counter_block;
		if (!GenerateCounterBlock(iv_str, &counter_block))
		{
			error_message_ = "Could not generate counter block";
			return false;
		}

		if (!encryptor.SetCounter(counter_block))
		{
			error_message_ = "Could not set counter";
			return false;
		}

		const string data_to_encrypt(reinterpret_cast<const char*>(plaintext), size);
		string encrypted_text;
		if (!encryptor.Encrypt(data_to_encrypt, &encrypted_text))
		{
			error_message_ = "Could not encrypt data";
			return false;
		}

		// Prepend the IV.
		cipher_temp_size += kIVSize;
		if (*ciphertext_size < cipher_temp_size)
		{
			*ciphertext_size = cipher_temp_size;
			error_message_ = "Insufficient memory";
			return false;
		}
		*ciphertext_size = cipher_temp_size;

		memcpy(ciphertext + kSignalByteSize, &iv, kIVSize);
		memcpy(ciphertext + kIVSize + kSignalByteSize, encrypted_text.data(), encrypted_text.size());
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

	const uint8 signal_byte = do_not_encrypt_ ? 0 : kEncryptedFrame;
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
