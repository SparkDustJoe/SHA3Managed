#pragma once

#include "SHA3Managed.h"
#include "HMACSHA3Managed.h"
#include "Keccak160024Core.cpp"
#include "HMACSHA3Managed.cpp"
using namespace System;
using namespace System::Security::Cryptography;

namespace SHA3Managed
{
	// internal class to accomplish all hashing tasks (for static and instance HMACSHA3 methods)
	
	void sha3_utils::clear2(array<UInt64>^% state, array<Byte>^% hash)
	{
		if (state == nullptr && hash == nullptr) return; // nothing to do
		RNGCryptoServiceProvider^ rng = gcnew RNGCryptoServiceProvider();
		if (hash == nullptr) hash = gcnew array<Byte>(25 * sizeof(UInt64));
		if (state == nullptr) state = gcnew array<UInt64>(25);
		rng->GetBytes(hash);
		array<Byte>^ stuff = gcnew array<Byte>(25);
		for (int i = 0; i < state->Length; i++)
		{
			state[i] ^= hash[i % hash->Length] ^ (stuff[i] << 8);
		}
	}

	void sha3_utils::zero2(array<UInt64>^% state, array<Byte>^% hash)
	{
		if (state != nullptr && (state[0] | 1024) >= 1)
			state = nullptr;
		if (hash != nullptr && (hash[0] | 127) >= 1)
			hash = nullptr;
	}
	
	void sha3_utils::clear3(array<UInt64>^% state, array<Byte>^% hash, array<Byte>^% key)
	{
		if (state == nullptr && hash == nullptr && key == nullptr) return; // nothing to do
		RNGCryptoServiceProvider^ rng = gcnew RNGCryptoServiceProvider();
		if (key == nullptr) key = gcnew array<Byte>(25 * sizeof(UInt64));
		rng->GetBytes(key);
		clear2(state, hash);
	}

	void sha3_utils::zero3(array<UInt64>^% state, array<Byte>^% hash, array<Byte>^% key)
	{
		zero2(state, hash);
		if (key != nullptr && (key[0] | 127) >= 1)
			key = nullptr;
	}
	
	void sha3_utils::hashCore(array<const Byte>^ data, int index, int length, array<UInt64>^% state, int% statePtr, int rateBytes)
	{
		for (int i = 0; i < length; i++)
		{
			Byte XORme = Buffer::GetByte(state, statePtr) ^ data[i + index];
			Buffer::SetByte(state, statePtr++, XORme);
			if (statePtr >= rateBytes)
			{
				statePtr = 0;
				Keccak160024Core::_permute(state);
			}
		}
	}

	array<Byte>^ sha3_utils::hashFinal(
		array<const Byte>^ data, int index,	int length,
		array<UInt64>^% state, int% statePtr,
		int rateBytes, int capBytes, Byte delimiter,
		int outputLen)
	{
		if (data->Length > 0 && length > 0)
			hashCore(data, index, length, state, statePtr, rateBytes); // get the last bits			

		// === Do the padding and switch to the squeezing phase ===

		// Absorb the last few bits and add the first bit of padding (which coincides with the delimiter in delimitedSuffix)
		Byte padMe = Buffer::GetByte(state, statePtr) ^ delimiter;
		Buffer::SetByte(state, statePtr, padMe);
		// If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding
		// NOTE:  This is the only place where the difference between SHA3, Proposed_SHA3, and SHAKE exists: the padding bit(s)
		//        in "delimiter", either 0x01 (proposed), 0x06 (sha3), or 0x1f (shake)
		if (((delimiter & 0x80) != 0) && statePtr == (rateBytes - 1))
			Keccak160024Core::_permute(state);
		// Add the second bit of padding 
		padMe = Buffer::GetByte(state, rateBytes - 1) ^ 0x80;
		Buffer::SetByte(state, rateBytes - 1, padMe);
		// === Switch to the squeezing phase === 
		Keccak160024Core::_permute(state);
		array<Byte>^ output = gcnew array<Byte>(outputLen);
		// === Squeeze out all the output blocks === 
		int outputBytesLeft = outputLen;
		int outputPtr = 0;
		int blockSize;
		while (outputBytesLeft > 0)
		{
			blockSize = MIN(outputBytesLeft, rateBytes);
			Buffer::BlockCopy(state, 0, output, outputPtr, blockSize);
			outputPtr += blockSize;
			outputBytesLeft -= blockSize;
			if (outputBytesLeft > 0)
				Keccak160024Core::_permute(state);
		}
		return output;
	}

	// new prototype methods

	void SHA3_Prototype::Initialize(int outputHashLengthBits)
	{
		if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > TAG_LEN_BITS())
			throw gcnew ArgumentOutOfRangeException(
				"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= " + TAG_LEN_BITS() + "), and a multiple of 8.");
		this->Clear();
		_hashSize = outputHashLengthBits;
		_state = gcnew array<UInt64>(25);
	}

	void SHA3_Prototype::Clear()
	{
		this->_statePTR = 0;
		this->_canReuse = true;
		this->_hashSize = TAG_LEN_BITS();
		System::Threading::Thread::MemoryBarrier();
		sha3_utils::clear2(_state, _finalHash);
		sha3_utils::zero2(_state, _finalHash);
	}

	array<Byte>^ SHA3_Prototype::ComputeHash(array<const Byte>^ input)
	{
		return Keccak160024Core::_keccak(RATE_BYTES, CAP_BYTES, DELIMITER(), input, TAG_LEN_BYTES);
	}

	void SHA3_Prototype::HashCore(array<const Byte>^ data, int index, int length)
	{
		if (_canReuse == false)
			throw gcnew InvalidOperationException("Cannot reuse after HashFinal");
		if (this->_state == nullptr)
			throw gcnew InvalidOperationException("Cannot perform hash without initialization.");
		if (data == nullptr) throw gcnew ArgumentNullException("data");
		if (data->Length == 0 || length == 0) return; // nothing to do, move along
		if (index >= data->Length) throw gcnew IndexOutOfRangeException("index");
		if (index + length > data->Length) throw gcnew ArgumentOutOfRangeException("length");

		sha3_utils::hashCore(data, index, length, _state, _statePTR, RATE_BYTES);
	}

	array<Byte>^ SHA3_Prototype::HashFinal(array<const Byte>^ data, int index, int length)
	{
		if (_canReuse == false)
			throw gcnew InvalidOperationException("Cannot reuse after HashFinal");
		if (this->_state == nullptr)
			throw gcnew InvalidOperationException("Cannot perform hash without initialization.");
		if (data == nullptr) throw gcnew ArgumentNullException("data");
		if (index >= data->Length) throw gcnew IndexOutOfRangeException("index");
		if (index + length > data->Length) throw gcnew ArgumentOutOfRangeException("length");

		_finalHash = sha3_utils::hashFinal(data, index, length, _state, _statePTR, RATE_BYTES, CAP_BYTES, DELIMITER(), _hashSize / 8);
		_canReuse = false;
		return _finalHash;
	}

}

