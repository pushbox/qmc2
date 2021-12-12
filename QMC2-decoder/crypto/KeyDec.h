#pragma once

#include <cstdint>

class KeyDec {
public:
	void GetKey(uint8_t*& key, size_t& key_size);
	~KeyDec();

private:
	uint8_t* key;
	size_t key_len;
};
