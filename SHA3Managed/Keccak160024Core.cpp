// Keccak Core (in 1600 bit variant with 24 rounds suitable for all SHA3 algorithms)

#pragma once

using namespace System;

namespace SHA3Managed
{
	namespace Keccak160024Core
	{
#define MIN(a,b)	(a < b ? a : b)

		static __inline UInt64 ROTL64(UInt64 x, Byte b)
		{
			return (x << b) | (x >> (64-b));
		}

		static void _permute(array<UInt64>^ state)
		{
			UInt64 C0, C1, C2, C3, C4, D0, D1, D2, D3, D4;
			// NOTE: ALL CONSTANTS ARE FOR KECCAK-f[1600], found here https://keccak.team/keccak_specs_summary.html
			array<UInt64>^ IRC = gcnew array<UInt64>{ // _iota round constants
				0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL, 
					0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL, 
					0x000000000000008AULL,	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL, 
					0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,	0x8000000000008003ULL, 
					0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL, 	
					0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
			for (Byte round = 0; round < 24; round++)
			{
				//_theta
				C0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
				C1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
				C2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
				C3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
				C4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];
				D0 = ROTL64(C1, 1) ^ C4;
				D1 = ROTL64(C2, 1) ^ C0;
				D2 = ROTL64(C3, 1) ^ C1;
				D3 = ROTL64(C4, 1) ^ C2;
				D4 = ROTL64(C0, 1) ^ C3;
				state[0] ^= D0; state[5] ^= D0; state[10] ^= D0; state[15] ^= D0; state[20] ^= D0;
				state[1] ^= D1; state[6] ^= D1; state[11] ^= D1; state[16] ^= D1; state[21] ^= D1;
				state[2] ^= D2; state[7] ^= D2; state[12] ^= D2; state[17] ^= D2; state[22] ^= D2;
				state[3] ^= D3; state[8] ^= D3; state[13] ^= D3; state[18] ^= D3; state[23] ^= D3;
				state[4] ^= D4; state[9] ^= D4; state[14] ^= D4; state[19] ^= D4; state[24] ^= D4;
				//_end theta

				// _rho and pi, no sense giving them their own functions since they can be unrolled and combined for speed/optimization, and to reduce stack		
				//state[0] is shifted by zero and does not move, so ignore until _iota step
				System::Threading::Thread::MemoryBarrier();
				UInt64 a1 = ROTL64(state[1], 1); 
				state[1] = ROTL64(state[6], 44);	state[6] = ROTL64(state[9], 20);	state[9] = ROTL64(state[22], 61);	state[22] = ROTL64(state[14], 39);
				state[14] = ROTL64(state[20], 18);	state[20] = ROTL64(state[2], 62);	state[2] = ROTL64(state[12], 43);	state[12] = ROTL64(state[13], 25);
				state[13] = ROTL64(state[19], 8);	state[19] = ROTL64(state[23], 56);	state[23] = ROTL64(state[15], 41);	state[15] = ROTL64(state[4], 27);
				state[4] = ROTL64(state[24], 14);	state[24] = ROTL64(state[21], 2);	state[21] = ROTL64(state[8], 55);	state[8] = ROTL64(state[16], 45);
				state[16] = ROTL64(state[5], 36);	state[5] = ROTL64(state[3], 28);	state[3] = ROTL64(state[18], 21);	state[18] = ROTL64(state[17], 15);
				state[17] = ROTL64(state[11], 10);	state[11] = ROTL64(state[7], 6);	state[7] = ROTL64(state[10], 3);	state[10] = a1;
				// end _rho and _pi

				// _chi			
				System::Threading::Thread::MemoryBarrier();
				for (Byte i = 0; i < 25; i += 5)
				{
					C0 = state[0 + i] ^ ((~state[1 + i]) & state[2 + i]);
					C1 = state[1 + i] ^ ((~state[2 + i]) & state[3 + i]);
					C2 = state[2 + i] ^ ((~state[3 + i]) & state[4 + i]);
					C3 = state[3 + i] ^ ((~state[4 + i]) & state[0 + i]);
					C4 = state[4 + i] ^ ((~state[0 + i]) & state[1 + i]);

					state[0 + i] = C0;		state[1 + i] = C1;		state[2 + i] = C2;		state[3 + i] = C3;		state[4 + i] = C4;
				}
				// end _chi

				// _iota	
				state[0] ^= IRC[round]; 		
			} // for round
		} // end _permute

		static array<Byte>^ _keccak(const Byte rateBytes, const Byte capacityBytes, const Byte delimiter, array<const Byte>^ input, const int outputByteLen)
		{
			/* adapted from the compact, reference implementation linked from https://keccak.team on GitHub */
			array<Byte>^ output = gcnew array<Byte>(outputByteLen);
			array<UInt64>^ state = gcnew array<UInt64>(25);
			unsigned int blockSize = 0;
			unsigned int i;
			Int64 inputByteLen = input->LongLength;
			Int64 inputPtr = 0, outputPtr = 0;
			
			/* === Absorb all the input blocks === */
			array<UInt64>^ temp = gcnew array<UInt64>(rateBytes / sizeof(UInt64));
			while (inputByteLen > 0) {
				blockSize = MIN(inputByteLen, rateBytes);
				for (i = 0; i < blockSize; i++)
				{
					Byte XORme = Buffer::GetByte(state, i) ^ input[i + inputPtr];
					Buffer::SetByte(state, i, XORme);
				}
				inputPtr += blockSize;
				inputByteLen -= blockSize;
				if (blockSize == rateBytes)
				{
					_permute(state);
					blockSize = 0;
				}
			}

			/* === Do the padding and switch to the squeezing phase === */

			/* Absorb the last few bits and add the first bit of padding (which coincides with the delimiter in delimitedSuffix) */
			Byte padMe = Buffer::GetByte(state, blockSize) ^ delimiter; 
			Buffer::SetByte(state, blockSize, padMe);
			/* If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding */
			if ((delimiter & 0x80 !=0) && blockSize == (rateBytes - 1))
				_permute(state);
			/* Add the second bit of padding */
			padMe = Buffer::GetByte(state, rateBytes-1) ^ 0x80;
			Buffer::SetByte(state, rateBytes - 1, padMe);
			/* Switch to the squeezing phase */
			_permute(state);

			/* === Squeeze out all the output blocks === */
			int outputBytesLeft = outputByteLen;
			while (outputBytesLeft > 0)
			{
				blockSize = MIN(outputBytesLeft, rateBytes);
				Buffer::BlockCopy(state, 0, output, outputPtr, blockSize);
				outputPtr += blockSize;
				outputBytesLeft -= blockSize;
				if (outputBytesLeft > 0)
					_permute(state);
			}
			return output;
		}

	}
}
