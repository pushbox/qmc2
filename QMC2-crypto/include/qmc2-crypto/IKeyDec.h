#pragma once
#include <cstdint>
#include <cstddef>

class IKeyDec {
protected:
	uint8_t* decoded_key = nullptr;
	virtual void GetKey(uint8_t*& key, size_t& key_size) = 0;
	virtual void SetKey(const char* key, const size_t key_size) = 0;
};
