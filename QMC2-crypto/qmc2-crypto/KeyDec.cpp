#include "qmc2-crypto/KeyDec.h"

#include <util/tc_base64.h>
#include <util/tc_tea.h>

#include <cstdio>
#include <cmath>
#include <vector>
#include <cassert>

using tars::TC_Base64;
using tars::TC_Tea;

void SimpleMakeKey(uint8_t seed, size_t len, uint8_t* buf) {
	for (int i = 0; len > i; ++i) {
		buf[i] = (uint8_t)(fabs(tan((float)seed + (double)i * 0.1)) * 100.0);
	}
}

KeyDec::~KeyDec()
{
	Uninit();
}

void KeyDec::Uninit() {
	if (key) {
		delete[] key;
		key = nullptr;
	}

	key_len = 0;
}

void KeyDec::GetKey(uint8_t*& key_out, size_t& key_len_out)
{
	if (key && key_len > 0) {
		key_len_out = key_len;
		key_out = new uint8_t[key_len];
		memcpy(key_out, key, key_len);
	}
	else {
		key_len_out = 0;
	}
}

void KeyDec::SetKey(const char* ekey, const size_t key_size)
{
	Uninit();
	size_t decode_len = key_size / 4 * 3 + 4;

	std::vector<uint8_t> ekey_decoded;
	ekey_decoded.resize(decode_len);

	uint8_t simple_key_buf[8] = { 0 };
	SimpleMakeKey(106, 8, simple_key_buf);
#if _DEBUG
	// 69 56 46 38 2b 20 15 0b
	assert(simple_key_buf[0] == 0x69);
	assert(simple_key_buf[1] == 0x56);
	assert(simple_key_buf[2] == 0x46);
	assert(simple_key_buf[3] == 0x38);
	assert(simple_key_buf[4] == 0x2b);
	assert(simple_key_buf[5] == 0x20);
	assert(simple_key_buf[6] == 0x15);
	assert(simple_key_buf[7] == 0x0b);
#endif

	TC_Base64 b64;
	decode_len = b64.decode(ekey, key_size, ekey_decoded.data());

	if (decode_len != 0x210) {
		fprintf(stderr, "ERROR: decoded key size is not 0x210, got %llx instead.\n", decode_len);
		return;
	}

	uint8_t tea_key[16] = {};
	for (int i = 0; i < 16; i += 2) {
		tea_key[i + 0] = simple_key_buf[i / 2];
		tea_key[i + 1] = ekey_decoded[i / 2];
	}

	key = new uint8_t[decode_len * 2]();

	// Copy first 8 bytes
	memcpy(key, ekey_decoded.data(), 8u);

	// Copy the rest
	std::vector<char> decrypted_buf;
	TC_Tea tea;
	tea.decrypt(reinterpret_cast<const char*>(tea_key), reinterpret_cast<const char*>(ekey_decoded.data()) + 8, decode_len - 8, decrypted_buf);
	key_len = decrypted_buf.size() + 8;
	memcpy(&key[8], decrypted_buf.data(), decrypted_buf.size());
}
