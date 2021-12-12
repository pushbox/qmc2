#include "KeyDec.h"

#include <memory.h>

KeyDec::~KeyDec()
{
	if (key) {
		delete[] key;
		key = nullptr;
	}

	if (key_len) {
		key_len = 0;
	}
}

void KeyDec::GetKey(uint8_t*& key, size_t& key_size)
{
	if (key && key_len > 0 && key) {
		key_size = key_len;
		key = new uint8_t[key_len];
		memcpy(key, this->key, key_len);
	} else {
		key_size = 0;
	}
}
