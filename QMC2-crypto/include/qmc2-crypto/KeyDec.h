#pragma once
#include "IKeyDec.h"
#include <cstddef>

class KeyDec : public IKeyDec {
public:
	KeyDec() {};
	~KeyDec();

	virtual void GetKey(uint8_t*& key, size_t& key_size) override;
	virtual void SetKey(const char* key, const size_t key_size) override;
	
private:
	uint8_t* key = nullptr;
	size_t key_len = 0;
};
