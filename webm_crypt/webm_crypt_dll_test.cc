#include <cstdlib>
#include <iostream>
#include <string>

#include "base/base_switches.h"
#include "base/basictypes.h"
#include "base/memory/scoped_ptr.h"
#include "mkvmuxer.hpp"
#include "mkvmuxerutil.hpp"
#include "mkvparser.hpp"
#include "mkvreader.hpp"
#include "mkvwriter.hpp"
#include "webm_constants.h"
#include "webm_endian.h"

#include "WebmCryptCommon.h"
#include "WebmEncryptModule.h"
#include "WebmDecryptModule.h"
#pragma comment(lib, "webm_crypt_dll_2013.lib")

namespace {

	using std::string;
	using mkvparser::ContentEncoding;
	using namespace webm_crypt_dll;

	const char WEBM_CRYPT_VERSION_STRING[] = "0.3.1.t";

	struct WebmEncryptModule_delete : public std::default_delete < WebmEncryptModule >
	{
		void operator()(WebmEncryptModule* ptr)
		{
			WebmEncryptModule::Destroy(ptr);
		}
	};

	struct WebmDecryptModule_delete : public std::default_delete < WebmDecryptModule >
	{
		void operator()(WebmDecryptModule* ptr)
		{
			WebmDecryptModule::Destroy(ptr);
		}
	};

	typedef std::unique_ptr<WebmEncryptModule, WebmEncryptModule_delete> WebmEncryptModulePtr;
	typedef std::unique_ptr<WebmDecryptModule, WebmDecryptModule_delete> WebmDecryptModulePtr;

	// Struct to hold file wide encryption settings.
	struct WebMCryptSettings {
		WebMCryptSettings()
			: input(),
			output(),
			video(true),
			audio(false),
			no_encryption(false),
			match_src_clusters(false),
			aud_enc(),
			vid_enc() {
		}

		// Path to input file.
		string input;

		// Path to output file.
		string output;

		// Flag telling if the video stream should be encrypted.
		bool video;

		// Flag telling if the audio stream should be encrypted.
		bool audio;

		// Flag telling if the app should not encrypt or decrypt the data. This
		// should only be used to test the other parts of the system.
		bool no_encryption;

		// Flag telling app to match the placement of the source WebM Clusters.
		bool match_src_clusters;

		// Encryption settings for the audio stream.
		EncryptionSettings aud_enc;

		// Encryption settings for the video stream.
		EncryptionSettings vid_enc;
	};

	void Usage() {
		printf("Usage: webm_crypt_dll_test -i <input> -o <output> [Main options] "
			"[audio options] [video options]\n");
		printf("\n");
		printf("Main options:\n");
		printf("  -h | -?               Show help.\n");
		printf("  -v                    Show version\n");
		printf("  -audio <bool>         Process audio stream. (Default false)\n");
		printf("  -video <bool>         Process video stream. (Default true)\n");
		printf("  -decrypt              Decrypt the stream. (Default encrypt)\n");
		printf("  -no_encryption        Test flag which will not encrypt or\n");
		printf("                        decrypt the data. (Default false)\n");
		printf("  -match_src_clusters   Flag to match source WebM (Default false)\n");
		printf("  \n");
		printf("-audio_options <string> Comma separated name value pair.\n");
		printf("  content_id=<string>   Encryption content ID. (Default empty)\n");
		printf("  initial_iv=<uint64>   Initial IV value. (Default random)\n");
		printf("  base_file=<string>    Path to base secret file. (Default\n");
		printf("                        empty)\n");
		printf("  \n");
		printf("-video_options <string> Comma separated name value pair.\n");
		printf("  content_id=<string>   Encryption content ID. (Default empty)\n");
		printf("  initial_iv=<uint64>   Initial IV value. (Default random)\n");
		printf("  base_file=<string>    Path to base secret file. (Default\n");
		printf("                        empty)\n");
	}


	// Opens and initializes the input and output WebM files. |input| path to the
	// input WebM file. |output| path to the output WebM file. |reader| WebM
	// reader class output parameter. |parser| WebM parser class output parameter.
	// |writer| WebM writer class output parameter. |muxer| WebM muxer class
	// output parameter.
	bool OpenWebMFiles(const string& input,
		const string& output,
		mkvparser::MkvReader* reader,
		scoped_ptr<mkvparser::Segment>* parser,
		mkvmuxer::MkvWriter* writer,
		scoped_ptr<mkvmuxer::Segment>* muxer) {
		if (!reader || !parser || !writer || !muxer)
			return false;

		if (reader->Open(input.c_str())) {
			fprintf(stderr, "Filename is invalid or error while opening.\n");
			return false;
		}

		long long pos = 0;  // NOLINT
		mkvparser::EBMLHeader ebml_header;
		if (ebml_header.Parse(reader, pos)) {
			fprintf(stderr, "File:%s is not WebM file.", input.c_str());
			return false;
		}

		mkvparser::Segment* parser_segment;
		int64 ret = mkvparser::Segment::CreateInstance(reader, pos, parser_segment);
		if (ret) {
			fprintf(stderr, "Segment::CreateInstance() failed.");
			return false;
		}
		parser->reset(parser_segment);

		ret = (*parser)->Load();
		if (ret < 0) {
			fprintf(stderr, "Segment::Load() failed.");
			return false;
		}

		const mkvparser::SegmentInfo* const segment_info = (*parser)->GetInfo();
		const int64 timeCodeScale = segment_info->GetTimeCodeScale();

		// Set muxer header info
		if (!writer->Open(output.c_str())) {
			fprintf(stderr, "Filename is invalid or error while opening.\n");
			return false;
		}

		muxer->reset(new (std::nothrow) mkvmuxer::Segment());  // NOLINT
		if (!(*muxer)->Init(writer)) {
			fprintf(stderr, "Could not initialize muxer segment!\n");
			return false;
		}
		(*muxer)->set_mode(mkvmuxer::Segment::kFile);

		// Set SegmentInfo element attributes
		mkvmuxer::SegmentInfo* const info = (*muxer)->GetSegmentInfo();
		info->set_timecode_scale(timeCodeScale);
		string app_str("webm_crypt_dll_test ");
		app_str += WEBM_CRYPT_VERSION_STRING;
		info->set_writing_app(app_str.c_str());
		return true;
	}

	// Reads data from |file| and sets it to |data|. Returns true on success.
	bool ReadDataFromFile(const string& file, string* data) {
		if (!data || file.empty())
			return false;

		FILE* const f = fopen(file.c_str(), "rb");
		if (!f)
			return false;

		fseek(f, 0, SEEK_END);
		const int key_size = ftell(f);
		fseek(f, 0, SEEK_SET);

		scoped_ptr<char[]> raw_key_buf(new (std::nothrow) char[key_size]);  // NOLINT
		const int bytes_read = fread(raw_key_buf.get(), 1, key_size, f);
		fclose(f);

		if (bytes_read != key_size)
			return false;

		data->assign(raw_key_buf.get(), bytes_read);
		return true;
	}

	// Reads the secret data from a file. If a secret file was not set the
	// function will generate the secret data. |secret| output string that
	// contains the secret data. Returns true on success.
	bool GetBaseSecret(const EncryptionSettings& enc, string* secret) {
		if (!secret)
			return false;

		if (!enc.base_secret_file.empty()) {
			// Check if there is a file on disk and if it contains any data.
			FILE* const f = fopen(enc.base_secret_file.c_str(), "rb");
			if (f) {
				fseek(f, 0, SEEK_END);
				const int data_size = ftell(f);
				fseek(f, 0, SEEK_SET);
				fclose(f);

				if (data_size > 0) {
					string data;
					if (!ReadDataFromFile(enc.base_secret_file, &data)) {
						fprintf(stderr, "Could not read base secret file:%s\n",
							enc.base_secret_file.c_str());
						return false;
					}

					if (data.length() != kKeySize) {
						fprintf(stderr, "Base secret file data != kKeySize. length:%zu\n",
							data.length());
						return false;
					}
					*secret = data;
					return true;
				}
			}
		}
		uint8 random_secret[kKeySize];
		if (!GenerateRandomData(kKeySize, random_secret)) {
			fprintf(stderr, "Error generating base secret data.\n");
			return false;
		}
		std::copy(random_secret, random_secret + kKeySize, std::back_inserter(*secret));
		return true;
	}

	// Outputs |data| to a file if |filename| does not already contain any data.
	// |filename| path to a file. May be empty. |default_name| path to a file if
	// the |filename| was not set. |data| is the data to output. Returns true on
	// success.
	bool OutputDataToFile(const string& filename,
		const string& default_name,
		const string& data) {
		string output_file;
		if (!filename.empty()) {
			FILE* const f = fopen(filename.c_str(), "rb");
			if (f) {
				// File was passed in.
				fclose(f);
			}
			else {
				output_file = filename;
			}
		}
		else {
			output_file = default_name;
		}

		// Output the data.
		if (!output_file.empty()) {
			FILE* const f = fopen(output_file.c_str(), "wb");
			if (!f) {
				fprintf(stderr, "Could not open file: %s for writing.\n",
					output_file.c_str());
				return false;
			}

			const size_t bytes_written = fwrite(data.data(), 1, data.size(), f);
			fclose(f);

			if (bytes_written != data.size()) {
				fprintf(stderr, "Error writing to file.\n");
				return false;
			}
		}

		return true;
	}

	double StringToDouble(const string& s) {
		return strtod(s.c_str(), NULL);
	}

	// Parse name value pair.
	bool ParseOption(const string& option, string* name, string* value) {
		if (!name || !value)
			return false;

		const size_t equal_sign = option.find_first_of('=');
		if (equal_sign == string::npos)
			return false;

		*name = option.substr(0, equal_sign);
		*value = option.substr(equal_sign + 1, string::npos);
		return true;
	}

	// Parse set of options for one stream.
	void ParseStreamOptions(const string& option_list, EncryptionSettings* enc) {
		size_t start = 0;
		size_t end = option_list.find_first_of(',');
		for (;;) {
			const string option = option_list.substr(start, end - start);
			string name;
			string value;
			if (ParseOption(option, &name, &value)) {
				if (name == "content_id") {
					enc->content_id = value;
				}
				else if (name == "initial_iv") {
					enc->initial_iv = strtoull(value.c_str(), NULL, 10);
				}
				else if (name == "base_file") {
					enc->base_secret_file = value;
				}
			}

			if (end == string::npos)
				break;
			start = end + 1;
			end = option_list.find_first_of(',', start);
		}
	}

	// Parse the WebM content encryption elements. |encoding| is the WebM
	// ContentEncoding elements. |enc| is the output parameter for one stream.
	// Returns true on success.
	bool ParseContentEncryption(const ContentEncoding& encoding,
		EncryptionSettings* enc) {
		if (!enc)
			return false;

		if (encoding.GetEncryptionCount() > 0) {
			// Only check the first encryption.
			const ContentEncoding::ContentEncryption* const encryption =
				encoding.GetEncryptionByIndex(0);
			if (!encryption)
				return false;

			if (encryption->key_id_len > 0) {
				enc->content_id.assign(reinterpret_cast<char*>(encryption->key_id),
					static_cast<size_t>(encryption->key_id_len));
			}
		}

		return true;
	}

	// Function to encrypt a WebM file. |webm_crypt| encryption settings for
	// the source and destination files. Returns 0 on success and <0 for an error.
	int WebMEncrypt(const WebMCryptSettings& webm_crypt) {
		mkvparser::MkvReader reader;
		mkvmuxer::MkvWriter writer;
		scoped_ptr<mkvparser::Segment> parser_segment;
		scoped_ptr<mkvmuxer::Segment> muxer_segment;
		const bool b = OpenWebMFiles(webm_crypt.input,
			webm_crypt.output,
			&reader,
			&parser_segment,
			&writer,
			&muxer_segment);
		if (!b) {
			fprintf(stderr, "Could not open WebM files.\n");
			return -1;
		}

		// Set Tracks element attributes
		const mkvparser::Tracks* const parser_tracks = parser_segment->GetTracks();
		uint32 i = 0;
		uint64 vid_track = 0;  // no track added
		uint64 aud_track = 0;  // no track added
		string aud_base_secret;
		string vid_base_secret;

		while (i != parser_tracks->GetTracksCount()) {
			const int track_num = i++;

			const mkvparser::Track* const parser_track =
				parser_tracks->GetTrackByIndex(track_num);

			if (parser_track == NULL)
				continue;

			const char* const track_name = parser_track->GetNameAsUTF8();
			const int64 track_type = parser_track->GetType();

			if (track_type == mkvparser::Track::kVideo) {
				// Get the video track from the parser
				const mkvparser::VideoTrack* const pVideoTrack =
					reinterpret_cast<const mkvparser::VideoTrack*>(parser_track);
				const int64 width = pVideoTrack->GetWidth();
				const int64 height = pVideoTrack->GetHeight();

				// Add the video track to the muxer. 0 tells muxer to decide on track
				// number.
				vid_track = muxer_segment->AddVideoTrack(static_cast<int>(width),
					static_cast<int>(height),
					0);
				if (!vid_track) {
					fprintf(stderr, "Could not add video track.\n");
					return -1;
				}

				mkvmuxer::VideoTrack* const video =
					reinterpret_cast<mkvmuxer::VideoTrack*>(
					muxer_segment->GetTrackByNumber(vid_track));
				if (!video) {
					fprintf(stderr, "Could not get video track.\n");
					return -1;
				}

				video->set_codec_id(parser_track->GetCodecId());

				if (track_name)
					video->set_name(track_name);

				const double rate = pVideoTrack->GetFrameRate();
				if (rate > 0.0) {
					video->set_frame_rate(rate);
				}

				if (webm_crypt.video) {
					if (!video->AddContentEncoding()) {
						fprintf(stderr, "Could not add ContentEncoding to video track.\n");
						return -1;
					}

					mkvmuxer::ContentEncoding* const encoding =
						video->GetContentEncodingByIndex(0);
					if (!encoding) {
						fprintf(stderr, "Could not add ContentEncoding to video track.\n");
						return -1;
					}

					mkvmuxer::ContentEncAESSettings* const aes =
						encoding->enc_aes_settings();
					if (!aes) {
						fprintf(stderr, "Error getting video ContentEncAESSettings.\n");
						return -1;
					}
					if (aes->cipher_mode() != mkvmuxer::ContentEncAESSettings::kCTR) {
						fprintf(stderr, "Cipher Mode is not CTR.\n");
						return -1;
					}

					if (!GetBaseSecret(webm_crypt.vid_enc, &vid_base_secret)) {
						fprintf(stderr, "Error generating base secret.\n");
						return -1;
					}

					string id = webm_crypt.vid_enc.content_id;
					if (id.empty()) {
						uint8_t random_id[kDefaultContentIDSize];
						// If the content id is empty, create a content id.
						if (!GenerateRandomData(kDefaultContentIDSize, random_id)) {
							fprintf(stderr, "Error generating content id data.\n");
							return -1;
						}
						std::copy(random_id, random_id + kDefaultContentIDSize, std::back_inserter(id));
					}
					if (!encoding->SetEncryptionID(
						reinterpret_cast<const uint8*>(id.data()), id.size())) {
						fprintf(stderr, "Could not set encryption id for video track.\n");
						return -1;
					}
				}
			}
			else if (track_type == mkvparser::Track::kAudio) {
				// Get the audio track from the parser
				const mkvparser::AudioTrack* const pAudioTrack =
					reinterpret_cast<const mkvparser::AudioTrack*>(parser_track);
				const int64 channels = pAudioTrack->GetChannels();
				const double sample_rate = pAudioTrack->GetSamplingRate();

				// Add the audio track to the muxer. 0 tells muxer to decide on track
				// number.
				aud_track = muxer_segment->AddAudioTrack(static_cast<int>(sample_rate),
					static_cast<int>(channels),
					0);
				if (!aud_track) {
					fprintf(stderr, "Could not add audio track.\n");
					return -1;
				}

				mkvmuxer::AudioTrack* const audio =
					reinterpret_cast<mkvmuxer::AudioTrack*>(
					muxer_segment->GetTrackByNumber(aud_track));
				if (!audio) {
					fprintf(stderr, "Could not get audio track.\n");
					return -1;
				}

				audio->set_codec_id(parser_track->GetCodecId());

				if (track_name)
					audio->set_name(track_name);

				if (pAudioTrack->GetCodecDelay())
					audio->set_codec_delay(pAudioTrack->GetCodecDelay());
				if (pAudioTrack->GetSeekPreRoll())
					audio->set_seek_pre_roll(pAudioTrack->GetSeekPreRoll());

				size_t private_size;
				const uint8* const private_data =
					pAudioTrack->GetCodecPrivate(private_size);
				if (private_size > 0) {
					if (!audio->SetCodecPrivate(private_data, private_size)) {
						fprintf(stderr, "Could not add audio private data.\n");
						return -1;
					}
				}

				const int64 bit_depth = pAudioTrack->GetBitDepth();
				if (bit_depth > 0)
					audio->set_bit_depth(bit_depth);

				if (webm_crypt.audio) {
					if (!audio->AddContentEncoding()) {
						fprintf(stderr, "Could not add ContentEncoding to audio track.\n");
						return -1;
					}

					mkvmuxer::ContentEncoding* const encoding =
						audio->GetContentEncodingByIndex(0);
					if (!encoding) {
						fprintf(stderr, "Could not add ContentEncoding to audio track.\n");
						return -1;
					}

					mkvmuxer::ContentEncAESSettings* const aes =
						encoding->enc_aes_settings();
					if (!aes) {
						fprintf(stderr, "Error getting audio ContentEncAESSettings.\n");
						return -1;
					}
					if (aes->cipher_mode() != mkvmuxer::ContentEncAESSettings::kCTR) {
						fprintf(stderr, "Cipher Mode is not CTR.\n");
						return -1;
					}

					if (!GetBaseSecret(webm_crypt.aud_enc, &aud_base_secret)) {
						fprintf(stderr, "Error generating base secret.\n");
						return -1;
					}

					string id = webm_crypt.aud_enc.content_id;
					if (id.empty()) {
						uint8_t random_id[kDefaultContentIDSize];
						// If the content id is empty, create a content id.
						if (!GenerateRandomData(kDefaultContentIDSize, random_id)) {
							fprintf(stderr, "Error generating content id data.\n");
							return -1;
						}
						std::copy(random_id, random_id + kDefaultContentIDSize, std::back_inserter(id));
					}
					if (!encoding->SetEncryptionID(
						reinterpret_cast<const uint8*>(id.data()), id.size())) {
						fprintf(stderr, "Could not set encryption id for video track.\n");
						return -1;
					}
				}
			}
		}

		// Set Cues element attributes
		muxer_segment->CuesTrack(vid_track);

		// Write clusters
		scoped_ptr<uint8[]> data;
		int data_len = 0;
		scoped_ptr<uint8[]> encrypted_data;
		size_t encrypted_data_len = 0;

		WebmEncryptModulePtr audio_encryptor(WebmEncryptModule::Create(aud_base_secret, webm_crypt.aud_enc.initial_iv));
		if (webm_crypt.audio && !audio_encryptor->Init()) {
			fprintf(stderr, "Could not initialize audio encryptor.\n");
			return -1;
		}
		audio_encryptor->set_do_not_encrypt(webm_crypt.no_encryption);

		WebmEncryptModulePtr video_encryptor(WebmEncryptModule::Create(vid_base_secret, webm_crypt.vid_enc.initial_iv));
		if (webm_crypt.video && !video_encryptor->Init()) {
			fprintf(stderr, "Could not initialize video encryptor.\n");
			return -1;
		}
		video_encryptor->set_do_not_encrypt(webm_crypt.no_encryption);

		const mkvparser::Cluster* prev_cluster = NULL;
		const mkvparser::Cluster* cluster = parser_segment->GetFirst();
		while ((cluster != NULL) && !cluster->EOS()) {
			const mkvparser::BlockEntry* block_entry;
			int status = cluster->GetFirst(block_entry);
			if (status)
				return -1;

			while ((block_entry != NULL) && !block_entry->EOS()) {
				const mkvparser::Block* const block = block_entry->GetBlock();
				const int64 trackNum = block->GetTrackNumber();
				const mkvparser::Track* const parser_track =
					parser_tracks->GetTrackByNumber(static_cast<uint32>(trackNum));
				const int64 track_type = parser_track->GetType();

				if ((track_type == mkvparser::Track::kAudio) ||
					(track_type == mkvparser::Track::kVideo)) {
					const int frame_count = block->GetFrameCount();
					const int64 time_ns = block->GetTime(cluster);
					const bool is_key = block->IsKey();

					for (int i = 0; i < frame_count; ++i) {
						const mkvparser::Block::Frame& frame = block->GetFrame(i);

						if (frame.len > data_len) {
							data.reset(new (std::nothrow) uint8[frame.len]);  // NOLINT
							if (!data.get())
								return -1;
							data_len = frame.len;
						}

						if (frame.Read(&reader, data.get()))
							return -1;

						if (frame.len + kSignalByteSize + kIVSize > encrypted_data_len) {
							encrypted_data.reset(new (std::nothrow) uint8[frame.len + kSignalByteSize + kIVSize]);
							if (!encrypted_data.get())
								return -1;
							encrypted_data_len = frame.len + kSignalByteSize + kIVSize;
						}

						if (webm_crypt.match_src_clusters && prev_cluster != cluster) {
							muxer_segment->ForceNewClusterOnNextFrame();
							prev_cluster = cluster;
						}

						const uint64 track_num =
							(track_type == mkvparser::Track::kAudio) ? aud_track : vid_track;

						if ((track_type == mkvparser::Track::kVideo && webm_crypt.video) ||
							(track_type == mkvparser::Track::kAudio && webm_crypt.audio)) {
							size_t ciphertext_size = encrypted_data_len;
							if (track_type == mkvparser::Track::kAudio) {
								if (!audio_encryptor->ProcessData(data.get(),
									frame.len,
									encrypted_data.get(),
									&ciphertext_size)) {
									fprintf(stderr, "Could not encrypt audio data.\n");
									return -1;
								}
							}
							else {
								if (!video_encryptor->ProcessData(data.get(),
									frame.len,
									encrypted_data.get(),
									&ciphertext_size)) {
									fprintf(stderr, "Could not encrypt video data.\n");
									return -1;
								}
							}

							if (!muxer_segment->AddFrame(
								encrypted_data.get(),
								ciphertext_size,
								track_num,
								time_ns,
								is_key)) {
								fprintf(stderr, "Could not add encrypted frame.\n");
								return -1;
							}

						}
						else {
							if (!muxer_segment->AddFrame(data.get(),
								frame.len,
								track_num,
								time_ns,
								is_key)) {
								fprintf(stderr, "Could not add frame.\n");
								return -1;
							}
						}
					}
				}

				status = cluster->GetNext(block_entry, block_entry);
				if (status)
					return -1;
			}

			cluster = parser_segment->GetNext(cluster);
		}

		muxer_segment->Finalize();

		// Output base secret data.
		if (!OutputDataToFile(webm_crypt.aud_enc.base_secret_file,
			"aud_base_secret.key",
			aud_base_secret)) {
			fprintf(stderr, "Error writing audio base secret to file.\n");
			return -1;
		}
		if (!OutputDataToFile(webm_crypt.vid_enc.base_secret_file,
			"vid_base_secret.key",
			vid_base_secret)) {
			fprintf(stderr, "Error writing video base secret to file.\n");
			return -1;
		}

		writer.Close();
		reader.Close();

		return 0;
	}

	// Function to decrypt a WebM file. |webm_crypt| encryption settings for
	// the source and destination files. Returns 0 on success and <0 for an error.
	int WebMDecrypt(const WebMCryptSettings& webm_crypt) {
		mkvparser::MkvReader reader;
		mkvmuxer::MkvWriter writer;
		scoped_ptr<mkvparser::Segment> parser_segment;
		scoped_ptr<mkvmuxer::Segment> muxer_segment;
		const bool b = OpenWebMFiles(webm_crypt.input,
			webm_crypt.output,
			&reader,
			&parser_segment,
			&writer,
			&muxer_segment);
		if (!b) {
			fprintf(stderr, "Could not open WebM files.\n");
			return -1;
		}

		// Set Tracks element attributes
		const mkvparser::Tracks* const parser_tracks = parser_segment->GetTracks();
		uint32 i = 0;
		uint64 vid_track = 0;  // no track added
		uint64 aud_track = 0;  // no track added
		EncryptionSettings aud_enc;
		EncryptionSettings vid_enc;
		bool decrypt_video = false;
		bool decrypt_audio = false;
		string aud_base_secret;
		string vid_base_secret;

		while (i != parser_tracks->GetTracksCount()) {
			const int track_num = i++;

			const mkvparser::Track* const parser_track =
				parser_tracks->GetTrackByIndex(track_num);

			if (parser_track == NULL)
				continue;

			const char* const track_name = parser_track->GetNameAsUTF8();
			const int64 track_type = parser_track->GetType();

			if (track_type == mkvparser::Track::kVideo) {
				// Get the video track from the parser
				const mkvparser::VideoTrack* const pVideoTrack =
					reinterpret_cast<const mkvparser::VideoTrack*>(parser_track);
				const int64 width = pVideoTrack->GetWidth();
				const int64 height = pVideoTrack->GetHeight();

				// Add the video track to the muxer. 0 tells muxer to decide on track
				// number.
				vid_track = muxer_segment->AddVideoTrack(static_cast<int>(width),
					static_cast<int>(height),
					0);
				if (!vid_track) {
					fprintf(stderr, "Could not add video track.\n");
					return -1;
				}

				mkvmuxer::VideoTrack* const video =
					reinterpret_cast<mkvmuxer::VideoTrack*>(
					muxer_segment->GetTrackByNumber(vid_track));
				if (!video) {
					fprintf(stderr, "Could not get video track.\n");
					return -1;
				}

				video->set_codec_id(parser_track->GetCodecId());

				if (track_name)
					video->set_name(track_name);

				const double rate = pVideoTrack->GetFrameRate();
				if (rate > 0.0) {
					video->set_frame_rate(rate);
				}

				// Check if the stream is encrypted.
				const int encoding_count = pVideoTrack->GetContentEncodingCount();
				if (encoding_count > 0) {
					// Only check the first content encoding.
					const ContentEncoding* const encoding =
						pVideoTrack->GetContentEncodingByIndex(0);
					if (!encoding) {
						fprintf(stderr, "Could not get first ContentEncoding.\n");
						return -1;
					}

					if (!ParseContentEncryption(*encoding, &vid_enc)) {
						fprintf(stderr, "Could not parse video ContentEncryption element.\n");
						return -1;
					}

					if (!ReadDataFromFile(webm_crypt.vid_enc.base_secret_file,
						&vid_base_secret)) {
						fprintf(stderr, "Could not read video base secret file:%s\n",
							webm_crypt.vid_enc.base_secret_file.c_str());
						return -1;
					}
					decrypt_video = true;
				}

			}
			else if (track_type == mkvparser::Track::kAudio) {
				// Get the audio track from the parser
				const mkvparser::AudioTrack* const pAudioTrack =
					reinterpret_cast<const mkvparser::AudioTrack*>(parser_track);
				const int64 channels = pAudioTrack->GetChannels();
				const double sample_rate = pAudioTrack->GetSamplingRate();

				// Add the audio track to the muxer. 0 tells muxer to decide on track
				// number.
				aud_track = muxer_segment->AddAudioTrack(static_cast<int>(sample_rate),
					static_cast<int>(channels),
					0);
				if (!aud_track) {
					fprintf(stderr, "Could not add audio track.\n");
					return -1;
				}

				mkvmuxer::AudioTrack* const audio =
					reinterpret_cast<mkvmuxer::AudioTrack*>(
					muxer_segment->GetTrackByNumber(aud_track));
				if (!audio) {
					fprintf(stderr, "Could not get audio track.\n");
					return -1;
				}

				audio->set_codec_id(parser_track->GetCodecId());

				if (track_name)
					audio->set_name(track_name);

				if (pAudioTrack->GetCodecDelay())
					audio->set_codec_delay(pAudioTrack->GetCodecDelay());
				if (pAudioTrack->GetSeekPreRoll())
					audio->set_seek_pre_roll(pAudioTrack->GetSeekPreRoll());

				size_t private_size;
				const uint8* const private_data =
					pAudioTrack->GetCodecPrivate(private_size);
				if (private_size > 0) {
					if (!audio->SetCodecPrivate(private_data, private_size)) {
						fprintf(stderr, "Could not add audio private data.\n");
						return -1;
					}
				}

				const int64 bit_depth = pAudioTrack->GetBitDepth();
				if (bit_depth > 0)
					audio->set_bit_depth(bit_depth);

				// Check if the stream is encrypted.
				const int encoding_count = pAudioTrack->GetContentEncodingCount();
				if (encoding_count > 0) {
					// Only check the first content encoding.
					const ContentEncoding* const encoding =
						pAudioTrack->GetContentEncodingByIndex(0);
					if (!encoding) {
						fprintf(stderr, "Could not get first ContentEncoding.\n");
						return -1;
					}

					if (!ParseContentEncryption(*encoding, &aud_enc)) {
						fprintf(stderr, "Could not parse audio ContentEncryption element.\n");
						return -1;
					}

					if (!ReadDataFromFile(webm_crypt.aud_enc.base_secret_file,
						&aud_base_secret)) {
						fprintf(stderr, "Could not read audio base secret file:%s\n",
							webm_crypt.aud_enc.base_secret_file.c_str());
						return -1;
					}
					decrypt_audio = true;
				}
			}
		}

		// Set Cues element attributes
		muxer_segment->CuesTrack(vid_track);

		// Write clusters
		scoped_ptr<uint8[]> data;
		int data_len = 0;
		scoped_ptr<uint8[]> decrypted_data;
		int decrypted_data_len = 0;
		WebmDecryptModulePtr audio_decryptor(WebmDecryptModule::Create(aud_base_secret));
		audio_decryptor->set_do_not_decrypt(webm_crypt.no_encryption);
		if (decrypt_audio && !audio_decryptor->Init()) {
			fprintf(stderr, "Could not initialize audio decryptor.\n");
			return -1;
		}

		WebmDecryptModulePtr video_decryptor(WebmDecryptModule::Create(vid_base_secret));
		video_decryptor->set_do_not_decrypt(webm_crypt.no_encryption);
		if (decrypt_video && !video_decryptor->Init()) {
			fprintf(stderr, "Could not initialize video decryptor.\n");
			return -1;
		}

		const mkvparser::Cluster* cluster = parser_segment->GetFirst();
		while ((cluster != NULL) && !cluster->EOS()) {
			const mkvparser::BlockEntry* block_entry;
			int status = cluster->GetFirst(block_entry);
			if (status)
				return -1;

			while ((block_entry != NULL) && !block_entry->EOS()) {
				const mkvparser::Block* const block = block_entry->GetBlock();
				const int64 trackNum = block->GetTrackNumber();
				const mkvparser::Track* const parser_track =
					parser_tracks->GetTrackByNumber(static_cast<uint32>(trackNum));
				const int64 track_type = parser_track->GetType();

				if ((track_type == mkvparser::Track::kAudio) ||
					(track_type == mkvparser::Track::kVideo)) {
					const int frame_count = block->GetFrameCount();
					const int64 time_ns = block->GetTime(cluster);
					const bool is_key = block->IsKey();

					for (int i = 0; i < frame_count; ++i) {
						const mkvparser::Block::Frame& frame = block->GetFrame(i);

						if (frame.len > data_len) {
							data.reset(new (std::nothrow) uint8[frame.len]);  // NOLINT
							if (!data.get())
								return -1;
							data_len = frame.len;
						}

						if (frame.Read(&reader, data.get()))
							return -1;

						if (frame.len > decrypted_data_len) {
							decrypted_data.reset(new (std::nothrow) uint8[frame.len]);
							if (!decrypted_data.get())
								return -1;
							decrypted_data_len = frame.len;
						}

						const uint64 track_num =
							(track_type == mkvparser::Track::kAudio) ? aud_track : vid_track;

						size_t decrypted_len = decrypted_data_len;
						if ((track_type == mkvparser::Track::kVideo && decrypt_video) ||
							(track_type == mkvparser::Track::kAudio && decrypt_audio)) {
							if (track_type == mkvparser::Track::kAudio) {
								if (!audio_decryptor->DecryptData(data.get(),
									frame.len,
									decrypted_data.get(),
									&decrypted_len)) {
									fprintf(stderr, "Could not decrypt audio data.\n");
									return -1;
								}
							}
							else {
								if (!video_decryptor->DecryptData(data.get(),
									frame.len,
									decrypted_data.get(),
									&decrypted_len)) {
									fprintf(stderr, "Could not decrypt video data.\n");
									return -1;
								}
							}

							if (decrypted_len) {
								if (!muxer_segment->AddFrame(
									decrypted_data.get(),
									decrypted_len,
									track_num,
									time_ns,
									is_key)) {
									fprintf(stderr, "Could not add encrypted frame.\n");
									return -1;
								}
							}

						}
						else {
							if (!muxer_segment->AddFrame(data.get(),
								frame.len,
								track_num,
								time_ns,
								is_key)) {
								fprintf(stderr, "Could not add frame.\n");
								return -1;
							}
						}
					}
				}

				status = cluster->GetNext(block_entry, block_entry);
				if (status)
					return -1;
			}

			cluster = parser_segment->GetNext(cluster);
		}

		muxer_segment->Finalize();

		writer.Close();
		reader.Close();
		return 0;
	}

	bool CheckEncryptionOptions(const string& name,
		const EncryptionSettings& enc) {
		if (enc.cipher_mode != "CTR") {
			fprintf(stderr, "stream:%s Only CTR cipher mode supported. mode:%s\n",
				name.c_str(),
				enc.cipher_mode.c_str());
			return false;
		}

		return true;
	}

}  // namespace

//// These values are not getting compiled into base.lib.
//namespace switches {
//
//// Gives the default maximal active V-logging level; 0 is the default.
//// Normally positive values are used for V-logging levels.
//const char kV[]                             = "v";
//
//// Gives the per-module maximal V-logging levels to override the value
//// given by --v.  E.g. "my_module=2,foo*=3" would change the logging
//// level for all code in source files "my_module.*" and "foo*.*"
//// ("-inl" suffixes are also disregarded for this matching).
////
//// Any pattern containing a forward or backward slash will be tested
//// against the whole pathname and not just the module.  E.g.,
//// "*/foo/bar/*=2" would change the logging level for all code in
//// source files under a "foo/bar" directory.
//const char kVModule[]                       = "vmodule";
//
//}  // namespace switches

int main(int argc, char* argv[]) {
	WebMCryptSettings webm_crypt_settings;
	bool encrypt = true;

	// Create initial random IV values.
	if (!GenerateRandomUInt64(&webm_crypt_settings.aud_enc.initial_iv)) {
		fprintf(stderr, "Could not generate initial IV value.\n");
		return EXIT_FAILURE;
	}
	if (!GenerateRandomUInt64(&webm_crypt_settings.vid_enc.initial_iv)) {
		fprintf(stderr, "Could not generate initial IV value.\n");
		return EXIT_FAILURE;
	}

	// Parse command line options.
	const int argc_check = argc - 1;
	for (int i = 1; i < argc; ++i) {
		if (!strcmp("-h", argv[i]) || !strcmp("-?", argv[i])) {
			Usage();
			return 0;
		}
		else if (!strcmp("-v", argv[i])) {
			printf("version: %s\n", WEBM_CRYPT_VERSION_STRING);
		}
		else if (!strcmp("-i", argv[i]) && i++ < argc_check) {
			webm_crypt_settings.input = argv[i];
		}
		else if (!strcmp("-o", argv[i]) && i++ < argc_check) {
			webm_crypt_settings.output = argv[i];
		}
		else if (!strcmp("-audio", argv[i]) && i++ < argc_check) {
			webm_crypt_settings.audio = !strcmp("true", argv[i]);
		}
		else if (!strcmp("-video", argv[i]) && i++ < argc_check) {
			webm_crypt_settings.video = !strcmp("true", argv[i]);
		}
		else if (!strcmp("-decrypt", argv[i])) {
			encrypt = false;
		}
		else if (!strcmp("-no_encryption", argv[i]) && i++ < argc_check) {
			webm_crypt_settings.no_encryption = !strcmp("true", argv[i]);
		}
		else if (!strcmp("-match_src_clusters", argv[i]) && i++ < argc_check) {
			webm_crypt_settings.match_src_clusters = !strcmp("true", argv[i]);
		}
		else if (!strcmp("-audio_options", argv[i]) && i++ < argc_check) {
			string option_list(argv[i]);
			ParseStreamOptions(option_list, &webm_crypt_settings.aud_enc);
		}
		else if (!strcmp("-video_options", argv[i]) && i++ < argc_check) {
			string option_list(argv[i]);
			ParseStreamOptions(option_list, &webm_crypt_settings.vid_enc);
		}
		else {
			if (i == argc_check) {
				--i;
				printf("Unknown or invalid parameter. index:%d parameter:%s\n",
					i, argv[i]);
			}
			else {
				printf("Unknown parameter. index:%d parameter:%s\n", i, argv[i]);
			}
			return EXIT_FAILURE;
		}
	}

	// Check main parameters.
	if (webm_crypt_settings.input.empty()) {
		fprintf(stderr, "No input file set.\n");
		Usage();
		return EXIT_FAILURE;
	}
	if (webm_crypt_settings.output.empty()) {
		fprintf(stderr, "No output file set.\n");
		Usage();
		return EXIT_FAILURE;
	}

	if (encrypt) {
		if (webm_crypt_settings.audio &&
			!CheckEncryptionOptions("audio", webm_crypt_settings.aud_enc)) {
			Usage();
			return EXIT_FAILURE;
		}
		if (webm_crypt_settings.video &&
			!CheckEncryptionOptions("video", webm_crypt_settings.vid_enc)) {
			Usage();
			return EXIT_FAILURE;
		}

		const int rv = WebMEncrypt(webm_crypt_settings);
		if (rv < 0) {
			fprintf(stderr, "Error encrypting WebM file.\n");
			return EXIT_FAILURE;
		}
	}
	else {
		const int rv = WebMDecrypt(webm_crypt_settings);
		if (rv < 0) {
			fprintf(stderr, "Error decrypting WebM file.\n");
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}
