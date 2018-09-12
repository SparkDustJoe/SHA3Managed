#pragma once

#include "SHA3Managed.h"
#include "HMACSHA3Managed.h"
#include "Keccak160024Core.cpp"
using namespace System;
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

	// APPLY RFC 2104 / FIPS-198-1 HMAC TRANSFORMATION USING SHA3/SHAKE
	array<Byte>^ HMACSHA3_224::ComputeHash(array<const Byte>^ key, array<const Byte>^ input)
	{
		return HMAC::HMACOperation(key, input, 224 / 8, RATE_BYTES, CAP_BYTES, DELIMITER, 224 / 8);
	}

	array<Byte>^ HMACSHA3_256::ComputeHash(array<const Byte>^ key, array<const Byte>^ input)
	{
		return HMAC::HMACOperation(key, input, 256 / 8, RATE_BYTES, CAP_BYTES, DELIMITER, 256 / 8);
	}

	array<Byte>^ HMACSHA3_384::ComputeHash(array<const Byte>^ key, array<const Byte>^ input)
	{
		return HMAC::HMACOperation(key, input, 384 / 8, RATE_BYTES, CAP_BYTES, DELIMITER, 384 / 8);
	}

	array<Byte>^ HMACSHA3_512::ComputeHash(array<const Byte>^ key, array<const Byte>^ input)
	{
		return HMAC::HMACOperation(key, input, 512 / 8, RATE_BYTES, CAP_BYTES, DELIMITER, 512 / 8);
	}

	/*array<Byte>^ HMACSHAKE_128::ComputeHash(array<const Byte>^ key, array<const Byte>^ input, const int outputByteLen)
	{
		return HMAC::HMACOperation(key, input, RATE_BYTES, CAP_BYTES, DELIMETER, outputByteLen);
	}

	array<Byte>^ HMACSHAKE_256::ComputeHash(array<const Byte>^ key, array<const Byte>^ input, const int outputByteLen)
	{
		return HMAC::HMACOperation(key, input, RATE_BYTES, CAP_BYTES, DELIMETER, outputByteLen);
	} */  // no tests are defined for these operations, so they are left out!

	array<Byte>^ HMAC::HMACOperation(array<const Byte>^ key, array<const Byte>^ input, 
		const Byte taglen, 
		const Byte rate, const Byte cap, const Byte delimiter, 
		const int outputlen)
	{
		// blocklength = rate
		array<Byte>^ localKey = (key->Length > rate) ? // is the key too long? yes prehash, no use as is
			SHA3Managed::Keccak160024Core::_keccak(rate, cap, delimiter, key, taglen) : (array<Byte>^)key;
		array<Byte>^ hash_input1 = gcnew array<Byte>(rate + input->Length); // per the spec, key is always <= blocklen bytes (pre-hash if > blocklen)
		array<Byte>^ hash = gcnew array<Byte>(taglen); // the output from the first hash of HMAC
		array<Byte>^ hash_input2 = gcnew array<Byte>(rate + taglen); // per the spec, key is used again
		System::Buffer::BlockCopy(localKey, 0, hash_input1, 0, localKey->Length);
		System::Buffer::BlockCopy(localKey, 0, hash_input2, 0, localKey->Length);
		if (input != nullptr)
			System::Buffer::BlockCopy(input, 0, hash_input1, rate, input->Length);
		for (Byte i = 0; i < rate; i++)
		{
			hash_input1[i] ^= 0x36; // 00110110 IPAD
			hash_input2[i] ^= 0x5c; // 01011100 OPAD
		}
		//Diagnostics::Debug::Print("INPUT 1: " + BitConverter::ToString(hash_input1)->Replace("-", ""));
		hash = SHA3Managed::Keccak160024Core::_keccak(rate, cap, delimiter, (array<const Byte>^)hash_input1, taglen); // first hash
		//Diagnostics::Debug::Print("FIRST HASH: " + BitConverter::ToString(hash)->Replace("-", ""));
		System::Buffer::BlockCopy(hash, 0, hash_input2, rate, hash->Length);
		//Diagnostics::Debug::Print("INPUT 2: " + BitConverter::ToString(hash_input2)->Replace("-", ""));
		hash = SHA3Managed::Keccak160024Core::_keccak(rate, cap, delimiter, (array<const Byte>^)hash_input2, outputlen); // second hash
		//TODO wipe intermediary buffers to prevent leaks
		return hash;
	}

}

