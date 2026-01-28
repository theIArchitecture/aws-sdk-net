using System;
using System.Security.Cryptography;

namespace Amazon.Test
{
    public class MixedTest
    {
        public void TestHashingMethod()
        {
            var hasher = MD5.Create(); // VIOLATION: AWS-FIPS-CRYPTO-001
            byte[] data = new byte[] { 1, 2, 3 };
            var hash = hasher.ComputeHash(data);
        }
    }
}
