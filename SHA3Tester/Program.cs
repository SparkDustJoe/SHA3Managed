using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SHA3Managed;

namespace SHA3Managed.Tester
{
    class Program
    {
        static volatile int passes = 0;
        static volatile int fails = 0;
        
        static void Main(string[] args)
        {
            TestCases tc = new TestCases();
            byte[] result;
            for (int i = 0; i < 2; i++)
            {
                SHA3_224 sh224 = new SHA3_224(tc.SHA3_224[i].Result.Length * 8);
                SHA3_256 sh256 = new SHA3_256(tc.SHA3_256[i].Result.Length * 8);
                SHA3_384 sh384 = new SHA3_384(tc.SHA3_384[i].Result.Length * 8);
                SHA3_512 sh512 = new SHA3_512(tc.SHA3_512[i].Result.Length * 8);
                SHAKE128 shk128 = new SHAKE128(tc.SHAKE128[i].Result.Length * 8);
                SHAKE256 shk256 = new SHAKE256(tc.SHAKE256[i].Result.Length * 8);

                Console.WriteLine("SHA3 Test " + i + " - - - - - - - - -");
                result = sh224.ComputeHash(tc.SHA3_224[i].Input);
                if (CompareArrays(result, tc.SHA3_224[i].Result)) WritePASS("SHA3_224 TEST " + i);
                else WriteFAIL("SHA3_224 TEST " + i);

                result = sh256.ComputeHash(tc.SHA3_256[i].Input);
                if (CompareArrays(result, tc.SHA3_256[i].Result)) WritePASS("SHA3_256 TEST " + i);
                else WriteFAIL("SHA3_256 TEST " + i);

                result = sh384.ComputeHash(tc.SHA3_384[i].Input);
                if (CompareArrays(result, tc.SHA3_384[i].Result)) WritePASS("SHA3_384 TEST " + i);
                else WriteFAIL("SHA3_384 TEST " + i);

                result = sh512.ComputeHash(tc.SHA3_512[i].Input);
                if (CompareArrays(result, tc.SHA3_512[i].Result)) WritePASS("SHA3_512 TEST " + i);
                else WriteFAIL("SHA3_512 TEST " + i);

                result = shk128.ComputeHash(tc.SHAKE128[i].Input);
                if (CompareArrays(result, tc.SHAKE128[i].Result)) WritePASS("SHAKE128 TEST " + i);
                else WriteFAIL("SHAKE128 TEST " + i);

                result = shk256.ComputeHash(tc.SHAKE256[i].Input);
                if (CompareArrays(result, tc.SHAKE256[i].Result)) WritePASS("SHAKE256 TEST " + i);
                else WriteFAIL("SHAKE256 TEST " + i);

                result = SHA3_224.ComputeHash(tc.SHA3_224[i].Input, tc.SHA3_224[i].Result.Length * 8);
                if (CompareArrays(result, tc.SHA3_224[i].Result)) WritePASS("SHA3_224 STATIC METHOD TEST " + i);
                else WriteFAIL("SHA3_224 STATIC METHOD TEST " + i);

                result = SHA3_256.ComputeHash(tc.SHA3_256[i].Input, tc.SHA3_256[i].Result.Length * 8);
                if (CompareArrays(result, tc.SHA3_256[i].Result)) WritePASS("SHA3_256 STATIC METHOD TEST " + i);
                else WriteFAIL("SHA3_256 STATIC METHOD TEST " + i);

                result = SHA3_384.ComputeHash(tc.SHA3_384[i].Input, tc.SHA3_384[i].Result.Length * 8);
                if (CompareArrays(result, tc.SHA3_384[i].Result)) WritePASS("SHA3_384 STATIC METHOD TEST " + i);
                else WriteFAIL("SHA3_384 STATIC METHOD TEST " + i);

                result = SHA3_512.ComputeHash(tc.SHA3_512[i].Input, tc.SHA3_512[i].Result.Length * 8);
                if (CompareArrays(result, tc.SHA3_512[i].Result)) WritePASS("SHA3_512 STATIC METHOD TEST " + i);
                else WriteFAIL("SHA3_512 STATIC METHOD TEST " + i);

                result = SHAKE128.ComputeHash(tc.SHAKE128[i].Input, tc.SHAKE128[i].Result.Length);
                if (CompareArrays(result, tc.SHAKE128[i].Result)) WritePASS("SHAKE128 STATIC METHOD TEST " + i);
                else WriteFAIL("SHAKE128 STATIC METHOD TEST " + i);

                result = SHAKE256.ComputeHash(tc.SHAKE256[i].Input, tc.SHAKE256[i].Result.Length);
                if (CompareArrays(result, tc.SHAKE256[i].Result)) WritePASS("SHAKE256 STATIC METHOD TEST " + i);
                else WriteFAIL("SHAKE256 STATIC METHOD TEST " + i);

                // hashcore/hashfinal tests
                if (tc.SHA3_224[i].Input?.Length > 0)
                {
                    sh224.Initialize();
                    sh224.HashCore(tc.SHA3_224[i].Input, 0, 10);
                    sh224.HashFinal(tc.SHA3_224[i].Input, 10, tc.SHA3_224[i].Input.Length - 10);
                    if (CompareArrays(sh224.Hash, tc.SHA3_224[i].Result)) WritePASS("SHA3_224 TEST (HASHCORE/HASHFINAL) " + i);
                    else WriteFAIL("SHA3_224 TEST (HASHCORE/HASHFINAL) " + i);
                }

                if (tc.SHA3_256[i].Input?.Length > 0)
                {
                    sh256.Initialize();
                    sh256.HashCore(tc.SHA3_256[i].Input, 0, 10);
                    sh256.HashFinal(tc.SHA3_256[i].Input, 10, tc.SHA3_256[i].Input.Length - 10);
                    if (CompareArrays(sh256.Hash, tc.SHA3_256[i].Result)) WritePASS("SHA3_256 TEST (HASHCORE/HASHFINAL) " + i);
                    else WriteFAIL("SHA3_256 TEST (HASHCORE/HASHFINAL) " + i);
                }

                if (tc.SHA3_384[i].Input?.Length > 0)
                {
                    sh384.Initialize();
                    sh384.HashCore(tc.SHA3_384[i].Input, 0, 10);
                    sh384.HashFinal(tc.SHA3_384[i].Input, 10, tc.SHA3_384[i].Input.Length - 10);
                    if (CompareArrays(sh384.Hash, tc.SHA3_384[i].Result)) WritePASS("SHA3_384 TEST (HASHCORE/HASHFINAL) " + i);
                    else WriteFAIL("SHA3_384 TEST (HASHCORE/HASHFINAL) " + i);
                }

                if (tc.SHA3_512[i].Input?.Length > 0)
                {
                    sh512.Initialize();
                    sh512.HashCore(tc.SHA3_512[i].Input, 0, 10);
                    sh512.HashFinal(tc.SHA3_512[i].Input, 10, tc.SHA3_512[i].Input.Length - 10);
                    if (CompareArrays(sh512.Hash, tc.SHA3_512[i].Result)) WritePASS("SHA3_512 TEST (HASHCORE/HASHFINAL) " + i);
                    else WriteFAIL("SHA3_512 TEST (HASHCORE/HASHFINAL) " + i);
                }

                if (tc.SHAKE128[i].Input?.Length > 0)
                {
                    shk128.Initialize(tc.SHAKE128[i].Result.Length * 8);
                    shk128.HashCore(tc.SHAKE128[i].Input, 0, 10);
                    shk128.HashFinal(tc.SHAKE128[i].Input, 10, tc.SHAKE128[i].Input.Length - 10);
                    if (CompareArrays(shk128.Hash, tc.SHAKE128[i].Result)) WritePASS("SHAKE128 TEST (HASHCORE/HASHFINAL) " + i);
                    else WriteFAIL("SHAKE128 TEST (HASHCORE/HASHFINAL) " + i);
                }

                if (tc.SHAKE256[i].Input?.Length > 0)
                {
                    shk256.Initialize(tc.SHAKE256[i].Result.Length * 8);
                    shk256.HashCore(tc.SHAKE256[i].Input, 0, 10);
                    shk256.HashFinal(tc.SHAKE256[i].Input, 10, tc.SHAKE256[i].Input.Length - 10);
                    if (CompareArrays(shk256.Hash, tc.SHAKE256[i].Result)) WritePASS("SHAKE256 TEST (HASHCORE/HASHFINAL) " + i);
                    else WriteFAIL("SHAKE256 TEST (HASHCORE/HASHFINAL) " + i);
                }

            }
            for (int i = 0; i < 4; i++)
            {
                Console.WriteLine("HMACSHA3 Test " + i + " - - - - - - - - -");
                //HMAC
                HMACSHA3_224 hm224 = new HMACSHA3_224(tc.HMACSHA3_224[i].Key, tc.HMACSHA3_224[i].Result.Length * 8);
                HMACSHA3_256 hm256 = new HMACSHA3_256(tc.HMACSHA3_256[i].Key, tc.HMACSHA3_256[i].Result.Length * 8);
                HMACSHA3_384 hm384 = new HMACSHA3_384(tc.HMACSHA3_384[i].Key, tc.HMACSHA3_384[i].Result.Length * 8);
                HMACSHA3_512 hm512 = new HMACSHA3_512(tc.HMACSHA3_512[i].Key, tc.HMACSHA3_512[i].Result.Length * 8);

                result = hm224.ComputeHash(tc.HMACSHA3_224[i].Input);
                if (CompareArrays(result, tc.HMACSHA3_224[i].Result)) WritePASS("HMACSHA3_224 TEST " + i);
                else WriteFAIL("HMACSHA3_224 TEST " + i);

                result = hm256.ComputeHash(tc.HMACSHA3_256[i].Input);
                if (CompareArrays(result, tc.HMACSHA3_256[i].Result)) WritePASS("HMACSHA3_256 TEST " + i);
                else WriteFAIL("HMACSHA3_256 TEST " + i);

                result = hm384.ComputeHash(tc.HMACSHA3_384[i].Input);
                if (CompareArrays(result, tc.HMACSHA3_384[i].Result)) WritePASS("HMACSHA3_384 TEST " + i);
                else WriteFAIL("HMACSHA3_384 TEST " + i);

                result = hm512.ComputeHash(tc.HMACSHA3_512[i].Input);
                if (CompareArrays(result, tc.HMACSHA3_512[i].Result)) WritePASS("HMACSHA3_512 TEST " + i);
                else WriteFAIL("HMACSHA3_512 TEST " + i);

                // HMAC HASHCORE/HASHFINAL
                hm224.Initialize(tc.HMACSHA3_224[i].Key, tc.HMACSHA3_224[i].Result.Length * 8);
                hm224.HashCore(tc.HMACSHA3_224[i].Input, 0, 10);
                hm224.HashFinal(tc.HMACSHA3_224[i].Input, 10, tc.HMACSHA3_224[i].Input.Length - 10);
                if (CompareArrays(hm224.Hash, tc.HMACSHA3_224[i].Result)) WritePASS("HMACSHA3_224 TEST (HASHCORE/HASHFINAL) " + i);
                else WriteFAIL("HMACSHA3_224 TEST (HASHCORE/HASHFINAL) " + i);

                hm256.Initialize(tc.HMACSHA3_256[i].Key, tc.HMACSHA3_256[i].Result.Length * 8);
                hm256.HashCore(tc.HMACSHA3_256[i].Input, 0, 10);
                hm256.HashFinal(tc.HMACSHA3_256[i].Input, 10, tc.HMACSHA3_256[i].Input.Length - 10);
                if (CompareArrays(hm256.Hash, tc.HMACSHA3_256[i].Result)) WritePASS("HMACSHA3_256 TEST (HASHCORE/HASHFINAL) " + i);
                else WriteFAIL("HMACSHA3_256 TEST (HASHCORE/HASHFINAL) " + i);

                hm384.Initialize(tc.HMACSHA3_384[i].Key, tc.HMACSHA3_384[i].Result.Length * 8);
                hm384.HashCore(tc.HMACSHA3_384[i].Input, 0, 10);
                hm384.HashFinal(tc.HMACSHA3_384[i].Input, 10, tc.HMACSHA3_384[i].Input.Length - 10);
                if (CompareArrays(hm384.Hash, tc.HMACSHA3_384[i].Result)) WritePASS("HMACSHA3_384 TEST (HASHCORE/HASHFINAL) " + i);
                else WriteFAIL("HMACSHA3_384 TEST (HASHCORE/HASHFINAL) " + i);

                hm512.Initialize(tc.HMACSHA3_512[i].Key, tc.HMACSHA3_512[i].Result.Length * 8);
                hm512.HashCore(tc.HMACSHA3_512[i].Input, 0, 10);
                hm512.HashFinal(tc.HMACSHA3_512[i].Input, 10, tc.HMACSHA3_512[i].Input.Length - 10);
                if (CompareArrays(hm512.Hash, tc.HMACSHA3_512[i].Result)) WritePASS("HMACSHA3_512 TEST (HASHCORE/HASHFINAL) " + i);
                else WriteFAIL("HMACSHA3_512 TEST (HASHCORE/HASHFINAL) " + i);

                // no HMACSHAKE tests provided by NIST
            }

            Console.WriteLine("Proposed SHA3 - - - - - - - -");
            //a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a SHA3-256
            //c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 PROPOSED SHA3-256, more like Keccak-256
            result = Proposed_SHA3_256.ComputeHash(new byte[0], 256);
            if (CompareArrays(result, TestCases.StringToBytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")))
                WritePASS("PROPOSED SHA3-256 TEST 1");
            else
                WriteFAIL("PROPOSED SHA3-256 TEST 1");

            Console.WriteLine("\r\nPASSES : " + passes);
            Console.WriteLine("FAILS  : " + fails);
            Console.WriteLine("Press ENTER to exit...");
            Console.ReadLine();
        }

        static void WritePASS(string message)
        {
            ConsoleColor fg = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(message.PadLeft(40) + "  -PASS-");
            Console.ForegroundColor = fg;
            Interlocked.Add(ref passes, 1);
        }

        static void WriteFAIL(string message)
        {
            ConsoleColor fg = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(message.PadLeft(40) + "  *FAIL*");
            Console.ForegroundColor = fg;
            Interlocked.Add(ref fails, 1);
        }

        static bool CompareArrays(byte[] a, byte[] b)
        {
            if ((a == null & b != null) || (b == null & a != null))
                return false;
            if (a == null && b == null)
                return true;
            if (a.Length != b.Length)
                Console.WriteLine(string.Format("Length mismatch... a={0} b={1}", a.Length, b.Length));
            if (Math.Min(a.Length, b.Length) == 0)
                return false; // one of the arrays has nothing in it, that's not expected or correct
            for (int i = 0; i < Math.Min(a.Length, b.Length); i++)
            {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

    }
}
