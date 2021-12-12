#pragma once
#include <cstddef>
#include <cstdint>

class IStreamEncryptAndDecrypt {
public:
	IStreamEncryptAndDecrypt() {};
	~IStreamEncryptAndDecrypt() {};

	virtual void StreamEncrypt(uint64_t offset, uint8_t* buf, size_t len) = 0;
	virtual void StreamDecrypt(uint64_t offset, uint8_t* buf, size_t len) = 0;
};
