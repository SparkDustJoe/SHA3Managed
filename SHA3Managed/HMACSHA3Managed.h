// HMACSHA3Managed.h

#pragma once

using namespace System;
using namespace System::Security::Cryptography;

namespace SHA3Managed
{
	// internal class to accomplish all HMAC tasks (for static and instance HMACSHA3 methods) 
	private ref class hmacsha3_utils {
	internal:
		static array<const Byte>^ generateRandomKey(int size);
		static array<Byte>^ hmac(array<const Byte>^ key, array<const Byte>^ input, 
			const Byte tagByteLen, const Byte rate, const Byte cap, const Byte delimiter, const int outputlen);
		static void initialize(array<const Byte>^ key,
			array<UInt64>^% state, int rateBytes, int capBytes, Byte delimiter, short tagSize);
		static array<Byte>^ hashFinal(array<const Byte>^ data, int index, int length,
			array<UInt64>^% state, int% statePtr, array<Byte>^ key,
			int rateBytes, int capBytes, Byte delimiter, int tagLen, int outputLen);
	};

	public ref class HMACSHA3_Prototype abstract
	{
	protected:
		// DEFINED BY THE INHERITING CLASS
		virtual short RATE_BITS() { return 0; }; 
		virtual Byte DELIMITER() { return 0; };
		virtual short TAG_LEN_BITS() { return 0; };

		// the same for all inherited clases based on the above values
		Byte RATE_BYTES = RATE_BITS() / 8;
		Byte RATE_WORDS = RATE_BITS() / 64; // 64bit words
		short CAP_BITS = 1600 - RATE_BITS();
		Byte CAP_BYTES = CAP_BITS / 8;
		Byte CAP_WORDS = CAP_BITS / 64; // 64bit words
		short TAG_LEN_BYTES = TAG_LEN_BITS() / 8;

		// non-static
		array<Byte>^ _finalHash = nullptr;
		array<UInt64>^ _state = nullptr;
		array<Byte>^ _key = nullptr;
		int _statePTR = 0;
		bool _canReuse = true;
		int _hashSize = TAG_LEN_BITS();

	public:
		// non-static members
		virtual property array<const Byte>^ Key
		{	array<const Byte>^ get() { return (array<const Byte>^)_key; };
		internal: void set(array<const Byte>^ k) { Initialize(k); }
		}
		virtual property array<const Byte>^ Hash { virtual array<const Byte>^ get() { return (array<const Byte>^)_finalHash; } }
		virtual property int HashSize { virtual int get() { return _hashSize; } }
		virtual property bool CanReuseTransform { virtual bool get() { return _canReuse; }	}
		HMACSHA3_Prototype() { Initialize(); };
		HMACSHA3_Prototype(int outputHashLengthBits) { Initialize(outputHashLengthBits); };
		HMACSHA3_Prototype(array<const Byte>^ key) { Initialize(key); };
		HMACSHA3_Prototype(array<const Byte>^ key, int outputHashLengthBits) { Initialize(key, outputHashLengthBits); };
		virtual void Initialize();
		virtual void Initialize(int outputHashLengthBits);
		virtual void Initialize(array<const Byte>^ key);
		virtual void Initialize(array<const Byte>^ key, int outputHashLengthBits);
		virtual void Clear();
		virtual array<Byte>^ ComputeHash(array<const Byte>^ input);
		virtual void HashCore(array<const Byte>^ data, int index, int length);
		virtual array<Byte>^ HashFinal(array<const Byte>^ data, int index, int length);
		~HMACSHA3_Prototype() { this->Clear(); }
		!HMACSHA3_Prototype() {}
	};

	// actual classes with hash-size-specific variables set

	public ref class HMACSHA3_224 sealed : public HMACSHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 1152; } ;
		Byte DELIMITER() override { return 0x06; };
		short TAG_LEN_BITS() override { return 224; };
	public:
		HMACSHA3_224() : HMACSHA3_Prototype() { };
		HMACSHA3_224(int outputHashLengthBits) : HMACSHA3_Prototype(outputHashLengthBits) { };
		HMACSHA3_224(array<const Byte>^ key) : HMACSHA3_Prototype(key) { };
		HMACSHA3_224(array<const Byte>^ key, int outputHashLengthBits) : HMACSHA3_Prototype(key, outputHashLengthBits) { };
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 224)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 224), and a multiple of 8.");
			return Keccak160024Core::_keccak(144, 56, 0x06, input, outputHashLengthBits / 8);
		}
	};

	public ref class HMACSHA3_256 sealed : public HMACSHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 1088; };
		Byte DELIMITER() override { return 0x06; };
		short TAG_LEN_BITS() override { return 256; };
	public:
		HMACSHA3_256() : HMACSHA3_Prototype() { };
		HMACSHA3_256(int outputHashLengthBits) : HMACSHA3_Prototype(outputHashLengthBits) { };
		HMACSHA3_256(array<const Byte>^ key) : HMACSHA3_Prototype(key) { };
		HMACSHA3_256(array<const Byte>^ key, int outputHashLengthBits) : HMACSHA3_Prototype(key, outputHashLengthBits) { };
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 256)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 256), and a multiple of 8.");
			return Keccak160024Core::_keccak(136, 64, 0x06, input, outputHashLengthBits / 8);
		}
	};

	public ref class HMACSHA3_384 sealed : public HMACSHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 832; };
		Byte DELIMITER() override { return 0x06; };
		short TAG_LEN_BITS() override { return 384; };
	public:
		HMACSHA3_384() : HMACSHA3_Prototype() { };
		HMACSHA3_384(int outputHashLengthBits) : HMACSHA3_Prototype(outputHashLengthBits) { };
		HMACSHA3_384(array<const Byte>^ key) : HMACSHA3_Prototype(key) { };
		HMACSHA3_384(array<const Byte>^ key, int outputHashLengthBits) : HMACSHA3_Prototype(key, outputHashLengthBits) { };
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 384)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 384), and a multiple of 8.");
			return Keccak160024Core::_keccak(104, 96, 0x06, input, outputHashLengthBits / 8);
		}
	};

	public ref class HMACSHA3_512 sealed : public HMACSHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 576; };
		Byte DELIMITER() override { return 0x06; };
		short TAG_LEN_BITS() override { return 512; };
	public:
		HMACSHA3_512() : HMACSHA3_Prototype() { };
		HMACSHA3_512(int outputHashLengthBits) : HMACSHA3_Prototype(outputHashLengthBits) { };
		HMACSHA3_512(array<const Byte>^ key) : HMACSHA3_Prototype(key) { };
		HMACSHA3_512(array<const Byte>^ key, int outputHashLengthBits) : HMACSHA3_Prototype(key, outputHashLengthBits) { };
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 512)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 512), and a multiple of 8.");
			return Keccak160024Core::_keccak(72, 128, 0x06, input, outputHashLengthBits / 8);
		}
	};

	// PRODUCES VALUES FROM THE PROPOSED SHA3!!! NOT FIPS VALUES!!! 

	public ref class HMAC_Proposed_SHA3_224 sealed : public HMACSHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 1152; };
		Byte DELIMITER() override { return 0x01; };
		short TAG_LEN_BITS() override { return 224; };
	public:
		HMAC_Proposed_SHA3_224() : HMACSHA3_Prototype() { };
		HMAC_Proposed_SHA3_224(int outputHashLengthBits) : HMACSHA3_Prototype(outputHashLengthBits) { };
		HMAC_Proposed_SHA3_224(array<const Byte>^ key) : HMACSHA3_Prototype(key) { };
		HMAC_Proposed_SHA3_224(array<const Byte>^ key, int outputHashLengthBits) : HMACSHA3_Prototype(key, outputHashLengthBits) { };
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 224)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 224), and a multiple of 8.");
			return Keccak160024Core::_keccak(144, 56, 0x01, input, outputHashLengthBits / 8);
		}
	};

	public ref class HMAC_Proposed_SHA3_256 sealed : public HMACSHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 1088; };
		Byte DELIMITER() override { return 0x01; };
		short TAG_LEN_BITS() override { return 256; };
	public:
		HMAC_Proposed_SHA3_256() : HMACSHA3_Prototype() { };
		HMAC_Proposed_SHA3_256(int outputHashLengthBits) : HMACSHA3_Prototype(outputHashLengthBits) { };
		HMAC_Proposed_SHA3_256(array<const Byte>^ key) : HMACSHA3_Prototype(key) { };
		HMAC_Proposed_SHA3_256(array<const Byte>^ key, int outputHashLengthBits) : HMACSHA3_Prototype(key, outputHashLengthBits) { };
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 256)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 256), and a multiple of 8.");
			return Keccak160024Core::_keccak(136, 64, 0x01, input, outputHashLengthBits / 8);
		}
	};

	public ref class HMAC_Proposed_SHA3_384 sealed : public HMACSHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 832; };
		Byte DELIMITER() override { return 0x01; };
		short TAG_LEN_BITS() override { return 384; };
	public:
		HMAC_Proposed_SHA3_384() : HMACSHA3_Prototype() { };
		HMAC_Proposed_SHA3_384(int outputHashLengthBits) : HMACSHA3_Prototype(outputHashLengthBits) { };
		HMAC_Proposed_SHA3_384(array<const Byte>^ key) : HMACSHA3_Prototype(key) { };
		HMAC_Proposed_SHA3_384(array<const Byte>^ key, int outputHashLengthBits) : HMACSHA3_Prototype(key, outputHashLengthBits) { };
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 384)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 384), and a multiple of 8.");
			return Keccak160024Core::_keccak(104, 96, 0x01, input, outputHashLengthBits / 8);
		}
	};

	public ref class HMAC_Proposed_SHA3_512 sealed : public HMACSHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 576; };
		Byte DELIMITER() override { return 0x01; };
		short TAG_LEN_BITS() override { return 512; };
	public:
		HMAC_Proposed_SHA3_512() : HMACSHA3_Prototype() { };
		HMAC_Proposed_SHA3_512(int outputHashLengthBits) : HMACSHA3_Prototype(outputHashLengthBits) { };
		HMAC_Proposed_SHA3_512(array<const Byte>^ key) : HMACSHA3_Prototype(key) { };
		HMAC_Proposed_SHA3_512(array<const Byte>^ key, int outputHashLengthBits) : HMACSHA3_Prototype(key, outputHashLengthBits) { };
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 512)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 512), and a multiple of 8.");
			return Keccak160024Core::_keccak(72, 128, 0x01, input, outputHashLengthBits / 8);
		}
	};
	
	// No tests are given by NIST for HMACSHAKEx operations, so they are not included

}
