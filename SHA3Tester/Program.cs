using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SHA3Managed;

namespace SHA3Managed.Tester
{
    class Program
    {
        static void Main(string[] args)
        {
            TestCases tc = new TestCases();
            byte[] result;
            for (int i = 0; i < 2; i++)
            {
                result = SHA3_224.ComputeHash(tc.SHA3_224[i].Input);
                if (CompareArrays(result, tc.SHA3_224[i].Result)) WritePASS("SHA3_224 TEST " + i);
                else WriteFAIL("SHA3_224 TEST " + i);

                result = SHA3_256.ComputeHash(tc.SHA3_256[i].Input);
                if (CompareArrays(result, tc.SHA3_256[i].Result)) WritePASS("SHA3_256 TEST " + i);
                else WriteFAIL("SHA3_256 TEST " + i);

                result = SHA3_384.ComputeHash(tc.SHA3_384[i].Input);
                if (CompareArrays(result, tc.SHA3_384[i].Result)) WritePASS("SHA3_384 TEST " + i);
                else WriteFAIL("SHA3_384 TEST " + i);

                result = SHA3_512.ComputeHash(tc.SHA3_512[i].Input);
                if (CompareArrays(result, tc.SHA3_512[i].Result)) WritePASS("SHA3_512 TEST " + i);
                else WriteFAIL("SHA3_512 TEST " + i);

                result = SHAKE128.ComputeHash(tc.SHAKE128[i].Input, tc.SHAKE128[i].Result.Length);
                if (CompareArrays(result, tc.SHAKE128[i].Result)) WritePASS("SHAKE128 TEST " + i);
                else WriteFAIL("SHAKE128 TEST " + i);

                result = SHAKE256.ComputeHash(tc.SHAKE256[i].Input, tc.SHAKE256[i].Result.Length);
                if (CompareArrays(result, tc.SHAKE256[i].Result)) WritePASS("SHAKE256 TEST " + i);
                else WriteFAIL("SHAKE256 TEST " + i);

            }
            for (int i = 0; i < 4; i++)
            {
                //HMAC
                result = HMACSHA3_224.ComputeHash(tc.HMACSHA3_224[i].Key, tc.HMACSHA3_224[i].Input);
                if (CompareArrays(result, tc.HMACSHA3_224[i].Result)) WritePASS("HMACSHA3_224 TEST " + i);
                else WriteFAIL("HMACSHA3_224 TEST " + i);

                result = HMACSHA3_256.ComputeHash(tc.HMACSHA3_256[i].Key, tc.HMACSHA3_256[i].Input);
                if (CompareArrays(result, tc.HMACSHA3_256[i].Result)) WritePASS("HMACSHA3_256 TEST " + i);
                else WriteFAIL("HMACSHA3_256 TEST " + i);

                result = HMACSHA3_384.ComputeHash(tc.HMACSHA3_384[i].Key, tc.HMACSHA3_384[i].Input);
                if (CompareArrays(result, tc.HMACSHA3_384[i].Result)) WritePASS("HMACSHA3_384 TEST " + i);
                else WriteFAIL("HMACSHA3_384 TEST " + i);

                result = HMACSHA3_512.ComputeHash(tc.HMACSHA3_512[i].Key, tc.HMACSHA3_512[i].Input);
                if (CompareArrays(result, tc.HMACSHA3_512[i].Result)) WritePASS("HMACSHA3_512 TEST " + i);
                else WriteFAIL("HMACSHA3_512 TEST " + i);

                // no HMACSHAKE tests provided by NIST
            }

            Console.WriteLine("Press ENTER to exit...");
            Console.ReadLine();
        }

        static void WritePASS(string message)
        {
            ConsoleColor fg = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(message + "\t\t-PASS-");
            Console.ForegroundColor = fg;
        }
        static void WriteFAIL(string message)
        {
            ConsoleColor fg = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(message + "\t\t*FAIL*");
            Console.ForegroundColor = fg;
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
