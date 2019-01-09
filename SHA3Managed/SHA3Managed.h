// SHA3Managed.h

#pragma once
#include "Keccak160024Core.cpp"
using namespace System;

namespace SHA3Managed {

	// internal class to accomplish all hashing tasks (for static and instance HMACSHA3 methods)
	private ref class sha3_utils
	{
	internal:
		static void clear2(array<UInt64>^% state, array<Byte>^% hash);
		static void zero2(array<UInt64>^% state, array<Byte>^% hash);
		static void clear3(array<UInt64>^% state, array<Byte>^% hash, array<Byte>^% key);
		static void zero3(array<UInt64>^% state, array<Byte>^% hash, array<Byte>^% key);
		static void hashCore(array<const Byte>^ data, int index, int length,
			array<UInt64>^% state, int% statePtr, int rateBytes);
		static array<Byte>^ hashFinal(array<const Byte>^ data, int index, int length,
			array<UInt64>^% state, int% statePtr,
			int rateBytes, int capBytes, Byte delimiter, int outputLen);
	};

	// new prototype abstract class
	
	public ref class SHA3_Prototype abstract
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
		int _statePTR = 0;
		bool _canReuse = true;
		int _hashSize = TAG_LEN_BITS();

	public:
		// non-static members
		virtual property array<const Byte>^ Hash { virtual array<const Byte>^ get() { return (array<const Byte>^)_finalHash; } }
		virtual property int HashSize { virtual int get() { return _hashSize; } }
		virtual property bool CanReuseTransform { virtual bool get() { return _canReuse; }	}
		SHA3_Prototype() { Initialize(TAG_LEN_BITS()); };
		SHA3_Prototype(int outputHashLengthBits) { Initialize(outputHashLengthBits); };
		virtual void Initialize() { Initialize(TAG_LEN_BITS()); };
		virtual void Initialize(int outputHashLengthBits);
		virtual void Clear();
		virtual array<Byte>^ ComputeHash(array<const Byte>^ input);
		virtual void HashCore(array<const Byte>^ data, int index, int length);
		virtual array<Byte>^ HashFinal(array<const Byte>^ data, int index, int length);
		~SHA3_Prototype() { this->Clear(); }
		!SHA3_Prototype() {}
	};

	// actual classes with hash-size-specific variables set

	public ref class SHA3_224 sealed : public SHA3_Prototype 
	{
	protected:
		short RATE_BITS() override { return 1152; };
		Byte DELIMITER() override { return 0x06; };
		short TAG_LEN_BITS() override { return 224; }
	public:
		SHA3_224() : SHA3_Prototype() {};
		SHA3_224(int outputHashLengthBits) : SHA3_Prototype(outputHashLengthBits) {};
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 224)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 224), and a multiple of 8.");
			return Keccak160024Core::_keccak(144, 56, 0x06, input, outputHashLengthBits / 8);
		}
	};

	public ref class SHA3_256 sealed : public SHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 1088; };
		Byte DELIMITER() override { return 0x06; };
		short TAG_LEN_BITS() override { return 256; }
	public:
		SHA3_256() : SHA3_Prototype() {};
		SHA3_256(int outputHashLengthBits) : SHA3_Prototype(outputHashLengthBits) {};
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 256)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 256), and a multiple of 8.");
			return Keccak160024Core::_keccak(136, 64, 0x06, input, outputHashLengthBits / 8);
		}
	};

	public ref class SHA3_384 sealed : public SHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 832; };
		Byte DELIMITER() override { return 0x06; };
		short TAG_LEN_BITS() override { return 384; }
	public:
		SHA3_384() : SHA3_Prototype() {};
		SHA3_384(int outputHashLengthBits) : SHA3_Prototype(outputHashLengthBits) {};
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 384)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 384), and a multiple of 8.");
			return Keccak160024Core::_keccak(104, 96, 0x06, input, outputHashLengthBits / 8);
		}
	};

	public ref class SHA3_512 sealed : public SHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 576; };
		Byte DELIMITER() override { return 0x06; };
		short TAG_LEN_BITS() override { return 512; }
	public:
		SHA3_512() : SHA3_Prototype() {};
		SHA3_512(int outputHashLengthBits) : SHA3_Prototype(outputHashLengthBits) {};
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 512)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 512), and a multiple of 8.");
			return Keccak160024Core::_keccak(72, 128, 0x06, input, outputHashLengthBits / 8);
		}
	};

	public ref class SHAKE128 sealed : public SHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 1344; };
		Byte DELIMITER() override { return 0x1f; };
	public:
		SHAKE128() : SHA3_Prototype() {};
		SHAKE128(int outputHashLengthBits) : SHA3_Prototype(outputHashLengthBits) {};
		void Initialize (int outputHashLengthBits) override
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are greater than 0, and a multiple of 8.");
			this->Clear();
			_hashSize = outputHashLengthBits;
			_state = gcnew array<UInt64>(25);
		}
		array<Byte>^ ComputeHash(array<const Byte>^ input) override
		{
			return Keccak160024Core::_keccak(RATE_BYTES, CAP_BYTES, DELIMITER(), input, _hashSize / 8);
		}
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputByteLen)
		{
			return Keccak160024Core::_keccak(168, 32, 0x1f, input, outputByteLen);
		}
	};

	public ref class SHAKE256 sealed : public SHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 1088; };
		Byte DELIMITER() override { return 0x1f; };
	public:
		SHAKE256() : SHA3_Prototype() {};
		SHAKE256(int outputHashLengthBits) : SHA3_Prototype(outputHashLengthBits) {};
		void Initialize (int outputHashLengthBits) override
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are greater than 0, and a multiple of 8.");
			this->Clear();
			_hashSize = outputHashLengthBits;
			_state = gcnew array<UInt64>(25);
		}
		array<Byte>^ ComputeHash(array<const Byte>^ input) override
		{
			return Keccak160024Core::_keccak(RATE_BYTES, CAP_BYTES, DELIMITER(), input, _hashSize / 8);
		}
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputByteLen)
		{
			return Keccak160024Core::_keccak(136, 64, 0x1f, input, outputByteLen);
		}
	};

	// PRODUCES VALUES FROM THE PROPOSED SHA3!!! NOT FIPS VALUES!!! 

	public ref class Proposed_SHA3_224 sealed : public SHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 1152; };
		Byte DELIMITER() override { return 0x01; };
		short TAG_LEN_BITS() override { return 224; }
	public:
		Proposed_SHA3_224() : SHA3_Prototype() {};
		Proposed_SHA3_224(int outputHashLengthBits) : SHA3_Prototype(outputHashLengthBits) {};
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 224)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 224), and a multiple of 8.");
			return Keccak160024Core::_keccak(144, 56, 0x01, input, outputHashLengthBits / 8);
		}
	};

	public ref class Proposed_SHA3_256 sealed : public SHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 1088; };
		Byte DELIMITER() override { return 0x01; };
		short TAG_LEN_BITS() override { return 256; }
	public:
		Proposed_SHA3_256() : SHA3_Prototype() {};
		Proposed_SHA3_256(int outputHashLengthBits) : SHA3_Prototype(outputHashLengthBits) {};
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 256)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 256), and a multiple of 8.");
			return Keccak160024Core::_keccak(136, 64, 0x01, input, outputHashLengthBits / 8);
		}
	};

	public ref class Proposed_SHA3_384 sealed : public SHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 832; };
		Byte DELIMITER() override { return 0x01; };
		short TAG_LEN_BITS() override { return 384; }
	public:
		Proposed_SHA3_384() : SHA3_Prototype() {};
		Proposed_SHA3_384(int outputHashLengthBits) : SHA3_Prototype(outputHashLengthBits) {};
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 384)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 384), and a multiple of 8.");
			return Keccak160024Core::_keccak(104, 96, 0x01, input, outputHashLengthBits / 8);
		}
	};

	public ref class Proposed_SHA3_512 sealed : public SHA3_Prototype
	{
	protected:
		short RATE_BITS() override { return 576; };
		Byte DELIMITER() override { return 0x01; };
		short TAG_LEN_BITS() override { return 512; }
	public:
		Proposed_SHA3_512() : SHA3_Prototype() {};
		Proposed_SHA3_512(int outputHashLengthBits) : SHA3_Prototype(outputHashLengthBits) {};
		// static members
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputHashLengthBits)
		{
			if (outputHashLengthBits <= 0 || outputHashLengthBits % 8 != 0 || outputHashLengthBits > 512)
				throw gcnew ArgumentOutOfRangeException(
					"outputHashLengthBits", "Output Hash Length, Acceptable values are in the range (0 < h <= 512), and a multiple of 8.");
			return Keccak160024Core::_keccak(72, 128, 0x01, input, outputHashLengthBits / 8);
		}
	};

	// HMAC headers included in a separate file under the same SHA3Managed namespace 
}
