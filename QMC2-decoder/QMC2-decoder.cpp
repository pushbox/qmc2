// QMC2-decoder.cpp : Defines the entry point for the application.
//

#include "QMC2-decoder.h"

// HACK: Make VS 2022 happy
#include "../QMC2-crypto/include/qmc2-crypto/StreamCencrypt.h"
#include "../QMC2-crypto/include/qmc2-crypto/KeyDec.h"

#include <cstring>

#include <iostream>
#include <fstream>
#include <string>

using namespace std;

StreamCencrypt* createInstWidthEKey(const char* ekey_b64) {
	StreamCencrypt* stream = new StreamCencrypt();
	KeyDec* key_dec = new KeyDec();
	key_dec->SetKey(ekey_b64, strlen(ekey_b64));
	stream->SetKeyDec(key_dec);
	delete key_dec;
	return stream;
}

constexpr size_t read_size = 4096;
constexpr size_t footer_detection_size = 0x40;
constexpr size_t encrypted_key_size = 704;

int main(int argc, char** argv)
{
	fprintf(stderr, "QMC2 decoder (cli) v1.0 by Jixun\n\n");

	if (argc < 3)
	{
		printf("usage: %s <input> <output> [ignored]\n", argv[0]);
		return 1;
	}

	ifstream mgg(argv[1], ios::in | ios::binary);
	ofstream ogg(argv[2], ios::out | ios::binary);

	uint64_t offset = 0;

	uint8_t buf[read_size] = {};
	mgg.seekg(0, ios::end);
	auto input_file_len = size_t(mgg.tellg());
	mgg.seekg(input_file_len - footer_detection_size, ios::beg);
	mgg.read(reinterpret_cast<char*>(buf), footer_detection_size);

	// Magic: 32 | 00 00 02 CC 51 54 61 67
	if (*(uint64_t*)(&buf[footer_detection_size - 8]) != 0x67615451CC020000
		|| (buf[footer_detection_size - 8 - 1]) != '2')
	{
		cout << "unknown encryption method" << endl;
		return 1;
	}

	size_t decrypted_file_size = 0;
	for (int i = 0; i < footer_detection_size; i++) {
		if (buf[i] == ',') {
			decrypted_file_size = input_file_len - footer_detection_size + i - encrypted_key_size;
			break;
		}
	}

	mgg.seekg(decrypted_file_size, ios::beg);
	mgg.read(reinterpret_cast<char*>(buf), encrypted_key_size);
	buf[encrypted_key_size] = 0;
	auto stream = createInstWidthEKey(reinterpret_cast<char*>(buf));
	mgg.seekg(0, ios::beg);

	size_t to_decrypt_len = decrypted_file_size;
	while (to_decrypt_len > 0) {
		auto block_size = std::min(read_size, to_decrypt_len);
		mgg.read(reinterpret_cast<char*>(buf), block_size);
		auto bytes_read = mgg.gcount();

		stream->StreamDecrypt(offset, buf, bytes_read);
		ogg.write(reinterpret_cast<char*>(buf), bytes_read);

		offset += bytes_read;
		to_decrypt_len -= bytes_read;
	}

	cout << "ok" << endl;

	return 0;
}
