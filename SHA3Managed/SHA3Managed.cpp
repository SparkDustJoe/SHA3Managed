#pragma once

#include "SHA3Managed.h"
#include "Keccak160024Core.cpp"

namespace SHA3Managed
{
	array<Byte>^ SHA3_224::ComputeHash(array<const Byte>^ input)
	{
		return SHA3Managed::Keccak160024Core::_keccak(RATE_BYTES, CAP_BYTES, DELIMITER, input, 224 / 8);
	}

	array<Byte>^ SHA3_256::ComputeHash(array<const Byte>^ input)
	{
		return SHA3Managed::Keccak160024Core::_keccak(RATE_BYTES, CAP_BYTES, DELIMITER, input, 256 / 8);
	}

	array<Byte>^ SHA3_384::ComputeHash(array<const Byte>^ input)
	{
		return SHA3Managed::Keccak160024Core::_keccak(RATE_BYTES, CAP_BYTES, DELIMITER, input, 384 / 8);
	}

	array<Byte>^ SHA3_512::ComputeHash(array<const Byte>^ input)
	{
		return SHA3Managed::Keccak160024Core::_keccak(RATE_BYTES, CAP_BYTES, DELIMITER, input, 512 / 8);
	}

	array<Byte>^ SHAKE128::ComputeHash(array<const Byte>^ input, const int outputByteLen)
	{
		return SHA3Managed::Keccak160024Core::_keccak(RATE_BYTES, CAP_BYTES, DELIMITER, input, outputByteLen);
	}

	array<Byte>^ SHAKE256::ComputeHash(array<const Byte>^ input, const int outputByteLen)
	{
		return SHA3Managed::Keccak160024Core::_keccak(RATE_BYTES, CAP_BYTES, DELIMITER, input, outputByteLen);
	}


}

