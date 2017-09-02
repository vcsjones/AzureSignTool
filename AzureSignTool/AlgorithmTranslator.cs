using System;
using System.Security.Cryptography;

namespace AzureSignTool
{
    internal static class AlgorithmTranslator
    {
        public static string SignatureAlgorithmToJwsAlgId(HashAlgorithmName hashAlgorithmName)
        {
                if (hashAlgorithmName.Name == HashAlgorithmName.SHA256.Name)
                    return "RS256";
                if (hashAlgorithmName.Name == HashAlgorithmName.SHA384.Name)
                    return "RS384";
                if (hashAlgorithmName.Name == HashAlgorithmName.SHA512.Name)
                    return "RS512";
                throw new NotSupportedException("The algorithm specified is not supported.");

        }

        public static uint HashAlgorithmToAlgId(HashAlgorithmName hashAlgorithmName)
        {
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA256.Name)
                return 0x0000800c;
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA384.Name)
                return 0x0000800d;
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA512.Name)
                return 0x0000800e;
            throw new NotSupportedException("The algorithm specified is not supported.");
        }

        public static string HashAlgorithmToOid(HashAlgorithmName hashAlgorithmName)
        {
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA1.Name)
                return "1.3.14.3.2.26";
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA256.Name)
                return "2.16.840.1.101.3.4.2.1";
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA384.Name)
                return "2.16.840.1.101.3.4.2.2";
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA512.Name)
                return "2.16.840.1.101.3.4.2.3";
            throw new NotSupportedException("The algorithm specified is not supported.");
        }
    }
}
