using System;
using System.Security.Cryptography;

namespace AzureSign.Core
{
    internal static class AlgorithmTranslator
    {
        public static uint HashAlgorithmToAlgId(HashAlgorithmName hashAlgorithmName)
        {
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA1.Name)
                return 0x00008004;
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA256.Name)
                return 0x0000800c;
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA384.Name)
                return 0x0000800d;
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA512.Name)
                return 0x0000800e;
            throw new NotSupportedException("The algorithm specified is not supported.");
        }

        public static string HashAlgorithmToOidAsciiTerminated(HashAlgorithmName hashAlgorithmName)
        {
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA1.Name)
                return "1.3.14.3.2.26\0";
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA256.Name)
                return "2.16.840.1.101.3.4.2.1\0";
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA384.Name)
                return "2.16.840.1.101.3.4.2.2\0";
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA512.Name)
                return "2.16.840.1.101.3.4.2.3\0";
            throw new NotSupportedException("The algorithm specified is not supported.");
        }
    }
}
