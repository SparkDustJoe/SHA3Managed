# SHA3Managed
A .Net C++/CLI implementation of NIST FIPS 202 SHA3 and SHAKE (Full Byte aligned output only)

*NEW* Breaking change! Some methods had a mix of specifying or displaying the HASH-length as byte-length or bit-length. All methods are now BIT-LENGTH inputs!

All primary classes are now inheriting from a base prototype abstract class with virtual methods to simplify debugging and dramatically shrink code.  The prototypes are public, but the classes I created are all SEALED.  SHAKE requires a little extra overriding to allow for hash-bit-lengths greater than the underlying hash function would normally allow (for example: SHA3_256 can only output up to 256 bits, but SHAKE128 can be much much longer, int.MaxValue bits to be exact, although I doubt anyone would do that).

Proposed_(HMAC)SHA3_x methods added (the padding/delimiter byte for the old functions for libraries created before FIPS 202 are all 0x01, whereas proper SHA3 is 0x06, and SHAKE is 0x1f).  This should make this library compatible with applications that expect the old behavior (such as Triplesec v3).
