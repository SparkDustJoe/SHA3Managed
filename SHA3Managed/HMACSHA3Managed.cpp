#pragma once

#include "SHA3Managed.h"
#include "HMACSHA3Managed.h"
#include "Keccak160024Core.cpp"
using namespace System;

namespace SHA3Managed
{
	// HMAC CLASS STATIC METHODS (used to generacize the other HMACSHA3 methods
	   
	array<const Byte>^ hmacsha3_utils::generateRandomKey(int size)
	{
		array<Byte>^ key1 = gcnew array<Byte>(size);
		array<Byte>^ key2 = gcnew array<Byte>(size * 2);
		RNGCryptoServiceProvider^ rng = gcnew RNGCryptoServiceProvider();
		rng->GetBytes(key1);
		rng->GetBytes(key2);
		for (short i = 0; i < size; i++)
		{
			key1[i] ^= key2[i] ^ key2[i + size]; // do some extra work to account for RNG failures
		}
		return (array<const Byte>^) key1;
	}

	array<Byte>^ hmacsha3_utils::hmac(array<const Byte>^ key, array<const Byte>^ input,
		const Byte tagByteLen,
		const Byte rate, const Byte cap, const Byte delimiter,
		const int outputlen)
	{
		// blocklength = rate
		array<Byte>^ localKey = (key->Length > rate) ? // is the key too long? yes prehash, no use as is
			Keccak160024Core::_keccak(rate, cap, delimiter, key, tagByteLen) : (array<Byte>^)key;
		array<Byte>^ hash_input1 = gcnew array<Byte>(rate + input->Length); // per the spec, key is always <= blocklen bytes (pre-hash if > blocklen)
		array<Byte>^ hash = gcnew array<Byte>(tagByteLen); // the output from the first hash of HMAC
		array<Byte>^ hash_input2 = gcnew array<Byte>(rate + tagByteLen); // per the spec, key is used again
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
		hash = Keccak160024Core::_keccak(rate, cap, delimiter, (array<const Byte>^)hash_input1, tagByteLen); // first hash
		//Diagnostics::Debug::Print("FIRST HASH: " + BitConverter::ToString(hash)->Replace("-", ""));
		System::Buffer::BlockCopy(hash, 0, hash_input2, rate, hash->Length);
		//Diagnostics::Debug::Print("INPUT 2: " + BitConverter::ToString(hash_input2)->Replace("-", ""));
		hash = Keccak160024Core::_keccak(rate, cap, delimiter, (array<const Byte>^)hash_input2, outputlen); // second hash
		//TODO wipe intermediary buffers to prevent leaks
		return hash;
	}

	// used to initialize instances
	void hmacsha3_utils::initialize(array<const Byte>^ key,
		array<UInt64>^% state, int rateBytes, int capBytes, Byte delimiter, short tagSizeBytes)
	{
		if (key == nullptr || key->Length == 0)
			throw gcnew InvalidOperationException("Cannot perform HMAC without a valid Key.");
		state = gcnew array<UInt64>(25);

		//INGEST FIRST PAD, key will be shortened to RATE_BYTES if longer
		array<Byte>^ localKey = (key->Length > rateBytes) ? // is the key too long? yes? prehash : no? use as is
			Keccak160024Core::_keccak(rateBytes, capBytes, delimiter, key, tagSizeBytes) : (array<Byte>^)key;
		Buffer::BlockCopy(localKey, 0, state, 0, localKey->Length); // pre-seed state with key
		Byte XORme = 0;
		for (Byte i = 0; i < rateBytes; i++) // add the padding to the state
		{
			XORme = Buffer::GetByte(state, i) ^ 0x36; // 00110110 IPAD
			Buffer::SetByte(state, i, XORme);
		}
		Keccak160024Core::_permute(state);
	}

	array<Byte>^ hmacsha3_utils::hashFinal(
		array<const Byte>^ data, int index, int length,
		array<UInt64>^% state, int% statePtr, 
		array<Byte>^ key, 
		int rateBytes, int capBytes, Byte delimiter, 
		int tagLen, int outputLen)
	{
		array<Byte>^ temp = SHA3Managed::sha3_utils::hashFinal(data, index, length, state, statePtr, rateBytes, capBytes, delimiter, tagLen);
		array<Byte>^ input2 = gcnew array<Byte>(rateBytes + tagLen);
		Buffer::BlockCopy(temp, 0, input2, rateBytes, temp->Length);

		sha3_utils::clear2(state, temp);

		// The inner pass is done, now time to do the outer (first hash is already in "temp")
		array<Byte>^ localKey = (key->Length > rateBytes)
			? Keccak160024Core::_keccak(rateBytes, capBytes, delimiter, (array<const Byte>^)key, tagLen)
			: (array<Byte>^)key;
		for (int i = 0; i < rateBytes; i++)
			if (i < localKey->Length)
				input2[i] = localKey[i] ^ 0x5c; // 01011100 OPAD
			else
				input2[i] = 0x5c;
		return Keccak160024Core::_keccak(rateBytes, capBytes, delimiter, (array<const Byte>^)input2, outputLen); // second hash
	}

	// new prototype methods

	void HMACSHA3_Prototype::Clear()
	{
		this->_statePTR = 0;
		this->_canReuse = true;
		this->_hashSize = TAG_LEN_BITS();
		System::Threading::Thread::MemoryBarrier();
		sha3_utils::clear3(_state, _finalHash, _key);
		sha3_utils::zero3(_state, _finalHash, _key);
	}

	void HMACSHA3_Prototype::Initialize()
	{
		this->Clear();
		_hashSize = TAG_LEN_BITS();
		this->_key = (array<Byte>^)hmacsha3_utils::generateRandomKey(64);
		hmacsha3_utils::initialize((array<const Byte>^)_key, _state, RATE_BYTES, CAP_BYTES, DELIMITER(), TAG_LEN_BITS());
	}

	void HMACSHA3_Prototype::Initialize(int outputHashLengthBits)
	{
		if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > TAG_LEN_BITS())
			throw gcnew ArgumentOutOfRangeException(
				"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= " + TAG_LEN_BITS() + "), and a multiple of 8.");
		this->Clear();
		_hashSize = outputHashLengthBits;
		this->_key = (array<Byte>^)hmacsha3_utils::generateRandomKey(64);
		hmacsha3_utils::initialize((array<const Byte>^)_key, _state, RATE_BYTES, CAP_BYTES, DELIMITER(), outputHashLengthBits / 8);
	}

	void HMACSHA3_Prototype::Initialize(array<const Byte>^ key)
	{
		if (key == nullptr || key->Length == 0)
			throw gcnew InvalidOperationException("Cannot perform HMAC without a valid Key (which must be specified when using this overloaded method)");
		this->Clear();
		_hashSize = TAG_LEN_BITS();
		hmacsha3_utils::initialize(key, _state, RATE_BYTES, CAP_BYTES, DELIMITER(), TAG_LEN_BITS());
		this->_key = (array<Byte>^)key->Clone();
	}

	void HMACSHA3_Prototype::Initialize(array<const Byte>^ key, int outputHashLengthBits)
	{
		if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > TAG_LEN_BITS())
			throw gcnew ArgumentOutOfRangeException(
				"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= " + TAG_LEN_BITS() + 
				"), and a multiple of 8.");
		if (key == nullptr || key->Length == 0)
			throw gcnew InvalidOperationException("Cannot perform HMAC without a valid Key (which must be specified when using this overloaded method)");
		this->Clear();
		_hashSize = outputHashLengthBits;
		hmacsha3_utils::initialize(key, _state, RATE_BYTES, CAP_BYTES, DELIMITER(), outputHashLengthBits / 8);
		this->_key = (array<Byte>^)key->Clone();
	}

	void HMACSHA3_Prototype::HashCore(array<const Byte>^ data, int index, int length)
	{
		if (this->Key == nullptr || Key->Length == 0)
			throw gcnew InvalidOperationException("Cannot perform HMAC without a valid Key.");
		if (_canReuse == false)
			throw gcnew InvalidOperationException("Cannot reuse HashCore after HashFinal");
		if (this->_state == nullptr)
			throw gcnew InvalidOperationException("Cannot perform HMAC without initialization.");
		if (data == nullptr) throw gcnew ArgumentNullException("data");
		if (data->Length == 0 || length == 0) return; // nothing to do, move along
		if (index >= data->Length) throw gcnew IndexOutOfRangeException("index");
		if (index + length > data->Length) throw gcnew ArgumentOutOfRangeException("length");

		sha3_utils::hashCore(data, index, length, this->_state, this->_statePTR, RATE_BYTES);
	}

	array<Byte>^ HMACSHA3_Prototype::HashFinal(array<const Byte>^ data, int index, int length)
	{
		if (this->Key == nullptr || Key->Length == 0)
			throw gcnew InvalidOperationException("Cannot perform HMAC without a valid Key.");
		if (_canReuse == false)
			throw gcnew InvalidOperationException("Cannot reuse Hash after HashFinal");
		if (this->_state == nullptr)
			throw gcnew InvalidOperationException("Cannot perform HMAC without initialization.");
		if (data == nullptr) throw gcnew ArgumentNullException("data");
		if (index >= data->Length) throw gcnew IndexOutOfRangeException("index");
		if (index + length > data->Length) throw gcnew ArgumentOutOfRangeException("length");

		_finalHash = hmacsha3_utils::hashFinal(data, index, length, _state, _statePTR, _key,
			RATE_BYTES, CAP_BYTES, DELIMITER(), TAG_LEN_BYTES, _hashSize / 8);
		_canReuse = false;
		return _finalHash;
	}

	array<Byte>^ HMACSHA3_Prototype::ComputeHash(array<const Byte>^ input)
	{
		if (this->_key == nullptr || _key->Length == 0)
			throw gcnew InvalidOperationException("Cannot perform HMAC without a valid Key. Run appropriate Initialize() method overload first.");
		return hmacsha3_utils::hmac(
			(array<const Byte>^)this->_key, input, TAG_LEN_BYTES, RATE_BYTES, CAP_BYTES, DELIMITER(), _hashSize / 8);
	};
	
}