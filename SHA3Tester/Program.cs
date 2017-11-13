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
            for (int i = 0; i < 2; i++)
            {
                byte[] result = SHA3_224.ComputeHash(tc.SHA3_224[i].Input);
                if (CompareArrays(result, tc.SHA3_224[i].Result))
                {
                    Console.WriteLine("SHA3_224 TEST " + i + "           -PASS-");
                }
                else
                {
                    Console.WriteLine("SHA3_224 TEST " + i + "           *FAIL!*");
                }
                result = SHA3_256.ComputeHash(tc.SHA3_256[i].Input);
                if (CompareArrays(result, tc.SHA3_256[i].Result))
                {
                    Console.WriteLine("SHA3_256 TEST " + i + "           -PASS-");
                }
                else
                {
                    Console.WriteLine("SHA3_256 TEST " + i + "           *FAIL!*");
                }
                result = SHA3_384.ComputeHash(tc.SHA3_384[i].Input);
                if (CompareArrays(result, tc.SHA3_384[i].Result))
                {
                    Console.WriteLine("SHA3_384 TEST " + i + "           -PASS-");
                }
                else
                {
                    Console.WriteLine("SHA3_384 TEST " + i + "           *FAIL!*");
                }
                result = SHA3_512.ComputeHash(tc.SHA3_512[i].Input);
                if (CompareArrays(result, tc.SHA3_512[i].Result))
                {
                    Console.WriteLine("SHA3_512 TEST " + i + "           -PASS-");
                }
                else
                {
                    Console.WriteLine("SHA3_512 TEST " + i + "           *FAIL!*");
                }
                result = SHAKE128.ComputeHash(tc.SHAKE128[i].Input, tc.SHAKE128[i].Result.Length);
                if (CompareArrays(result, tc.SHAKE128[i].Result))
                {
                    Console.WriteLine("SHAKE128 TEST " + i + "           -PASS-");
                }
                else
                {
                    Console.WriteLine("SHAKE128 TEST " + i + "           *FAIL!*");
                }
                result = SHAKE256.ComputeHash(tc.SHAKE256[i].Input, tc.SHAKE256[i].Result.Length);
                if (CompareArrays(result, tc.SHAKE256[i].Result))
                {
                    Console.WriteLine("SHAKE256 TEST " + i + "           -PASS-");
                }
                else
                {
                    Console.WriteLine("SHAKE256 TEST " + i + "           *FAIL!*");
                }
            }

            Console.WriteLine("Press ENTER to exit...");
            Console.ReadLine();
        }

        static bool CompareArrays(byte[] a, byte[] b)
        {
            if ((a == null & b != null) || (b == null & a != null))
                return false;
            if (a == null && b == null)
                return true;
            if (a.Length != b.Length)
                return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

    }
}
