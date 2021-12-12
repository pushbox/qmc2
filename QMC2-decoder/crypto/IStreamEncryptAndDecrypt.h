#pragma once

#include <cstdint>

class IStreamEncryptAndDecrypt {
	virtual void Decrypt(uint64_t offset, uint8_t* buf, size_t len) = 0;
	virtual void Encrypt(uint64_t offset, uint8_t* buf, size_t len) = 0;
};
