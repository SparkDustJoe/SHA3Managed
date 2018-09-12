// HMACSHA3Managed.h

#pragma once

using namespace System;

namespace SHA3Managed {

	public ref class HMACSHA3_224
	{
	internal:
		static const short RATE_BITS = 1152;
		static const Byte RATE_BYTES = RATE_BITS / 8;
		static const Byte RATE_WORDS = RATE_BITS / 64; // 64bit words
		static const short CAP_BITS = 1600 - RATE_BITS;
		static const Byte CAP_BYTES = CAP_BITS / 8;
		static const Byte CAP_WORDS = CAP_BITS / 64; // 64bit words
		static const Byte DELIMITER = 0x06;
	public:
		static array<Byte>^ ComputeHash(array<const Byte>^ key, array<const Byte>^ input);
		//array<Byte>^ ComputeHash(array<static const Byte>^ input, const int offset, const int length, const int outputByteLen);
	};

	public ref class HMACSHA3_256
	{
	internal:
		static const short RATE_BITS = 1088;
		static const Byte RATE_BYTES = RATE_BITS / 8;
		static const Byte RATE_WORDS = RATE_BITS / 64; // 64bit words
		static const short CAP_BITS = 1600 - RATE_BITS;
		static const Byte CAP_BYTES = CAP_BITS / 8;
		static const Byte CAP_WORDS = CAP_BITS / 64; // 64bit words
		static const Byte DELIMITER = 0x06;
	public:
		static array<Byte>^ ComputeHash(array<const Byte>^ key, array<const Byte>^ input);
		//array<Byte>^ ComputeHash(array<const Byte>^ input, const int offset, const int length, const int outputByteLen);
	};

	public ref class HMACSHA3_384
	{
	internal:
		static const short RATE_BITS = 832;
		static const Byte RATE_BYTES = RATE_BITS / 8;
		static const Byte RATE_WORDS = RATE_BITS / 64; // 64bit words
		static const short CAP_BITS = 1600 - RATE_BITS;
		static const Byte CAP_BYTES = CAP_BITS / 8;
		static const Byte CAP_WORDS = CAP_BITS / 64; // 64bit words
		static const Byte DELIMITER = 0x06;
	public:
		static array<Byte>^ ComputeHash(array<const Byte>^ key, array<const Byte>^ input);
		//array<Byte>^ ComputeHash(array<const Byte>^ input, const int offset, const int length, const int outputByteLen);
	};

	public ref class HMACSHA3_512
	{
	internal:
		static const short RATE_BITS = 576;
		static const Byte RATE_BYTES = RATE_BITS / 8;
		static const Byte RATE_WORDS = RATE_BITS / 64; // 64bit words
		static const short CAP_BITS = 1600 - RATE_BITS;
		static const Byte CAP_BYTES = CAP_BITS / 8;
		static const Byte CAP_WORDS = CAP_BITS / 64; // 64bit words
		static const Byte DELIMITER = 0x06;
	public:
		static array<Byte>^ ComputeHash(array<const Byte>^ key, array<const Byte>^ input);
		//array<Byte>^ ComputeHash(array<const Byte>^ input, const int offset, const int length, const int outputByteLen);
	};

	/*public ref class HMACSHAKE_128 {
	internal:
		static const short RATE_BITS = 1344;
		static const Byte RATE_BYTES = RATE_BITS / 8;
		static const Byte RATE_WORDS = RATE_BITS / 64; // 64bit words
		static const short CAP_BITS = 1600 - RATE_BITS;
		static const Byte CAP_BYTES = CAP_BITS / 8;
		static const Byte CAP_WORDS = CAP_BITS / 64; // 64bit words
		static const Byte DELIMITER = 0x1f;
	public:
		static array<Byte>^ ComputeHash(array<const Byte>^ key, array<const Byte>^ input, const int outputByteLen);
		//array<Byte>^ ComputeHash(array<const Byte>^ input, const int offset, const int length, const int outputByteLen);
	};

	public ref class HMACSHAKE_256 {
	internal:
		static const short RATE_BITS = 1088;
		static const Byte RATE_BYTES = RATE_BITS / 8;
		static const Byte RATE_WORDS = RATE_BITS / 64; // 64bit words
		static const short CAP_BITS = 1600 - RATE_BITS;
		static const Byte CAP_BYTES = CAP_BITS / 8;
		static const Byte CAP_WORDS = CAP_BITS / 64; // 64bit words
		static const Byte DELIMITER = 0x1f;
	public:
		static array<Byte>^ ComputeHash(array<const Byte>^ key, array<const Byte>^ input, const int outputByteLen);
		//array<Byte>^ ComputeHash(array<const Byte>^ input, const int offset, const int length, const int outputByteLen);
	}; */ // No tests are given by NIST for these operations, so they are not included

	private ref class HMAC {
	internal:
		static array<Byte>^ HMACOperation(array<const Byte>^ key, array<const Byte>^ input, const Byte taglen, const Byte rate, const Byte cap, const Byte delimiter, const int outputlen);
	};
}
