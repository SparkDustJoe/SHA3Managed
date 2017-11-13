// SHA3Managed.h

#pragma once

using namespace System;

namespace SHA3Managed {

	public ref class SHA3_224
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
		static array<Byte>^ ComputeHash(array<const Byte>^ input);
		//array<Byte>^ ComputeHash(array<static const Byte>^ input, const int offset, const int length, const int outputByteLen);
	};

	public ref class SHA3_256
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
		static array<Byte>^ ComputeHash(array<const Byte>^ input);
		//array<Byte>^ ComputeHash(array<const Byte>^ input, const int offset, const int length, const int outputByteLen);
	};

	public ref class SHA3_384
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
		static array<Byte>^ ComputeHash(array<const Byte>^ input);
		//array<Byte>^ ComputeHash(array<const Byte>^ input, const int offset, const int length, const int outputByteLen);
	};

	public ref class SHA3_512
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
		static array<Byte>^ ComputeHash(array<const Byte>^ input);
		//array<Byte>^ ComputeHash(array<const Byte>^ input, const int offset, const int length, const int outputByteLen);
	};

	public ref class SHAKE128 {
	internal:
		static const short RATE_BITS = 1344;
		static const Byte RATE_BYTES = RATE_BITS / 8;
		static const Byte RATE_WORDS = RATE_BITS / 64; // 64bit words
		static const short CAP_BITS = 1600 - RATE_BITS;
		static const Byte CAP_BYTES = CAP_BITS / 8;
		static const Byte CAP_WORDS = CAP_BITS / 64; // 64bit words
		static const Byte DELIMITER = 0x1f;
	public:
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputByteLen);
		//array<Byte>^ ComputeHash(array<const Byte>^ input, const int offset, const int length, const int outputByteLen);
	};

	public ref class SHAKE256 {
	internal:
		static const short RATE_BITS = 1088;
		static const Byte RATE_BYTES = RATE_BITS / 8;
		static const Byte RATE_WORDS = RATE_BITS / 64; // 64bit words
		static const short CAP_BITS = 1600 - RATE_BITS;
		static const Byte CAP_BYTES = CAP_BITS / 8;
		static const Byte CAP_WORDS = CAP_BITS / 64; // 64bit words
		static const Byte DELIMITER = 0x1f;
	public:
		static array<Byte>^ ComputeHash(array<const Byte>^ input, const int outputByteLen);
		//array<Byte>^ ComputeHash(array<const Byte>^ input, const int offset, const int length, const int outputByteLen);
	};

}
