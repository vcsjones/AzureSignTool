using System;
using System.Security.Cryptography;

namespace AzureSignTool
{
    internal static class AlgorithmTranslator
    {
        public static string SignatureAlgorithmToRsaJwsAlgId(HashAlgorithmName hashAlgorithmName)
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

        public static ReadOnlySpan<byte> HashAlgorithmToOidAsciiTerminated(HashAlgorithmName hashAlgorithmName)
        {
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA1.Name)
                return new byte[] { 0x31, 0x2e, 0x33, 0x2e, 0x31, 0x34, 0x2e, 0x33, 0x2e, 0x32, 0x2e, 0x32, 0x36, 0x00 };
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA256.Name)
                return new byte[] { 0x32, 0x2e, 0x31, 0x36, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x2e, 0x31, 0x30, 0x31, 0x2e, 0x33, 0x2e, 0x34, 0x2e, 0x32, 0x2e, 0x31, 0x00 };
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA384.Name)
                return new byte[] { 0x32, 0x2e, 0x31, 0x36, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x2e, 0x31, 0x30, 0x31, 0x2e, 0x33, 0x2e, 0x34, 0x2e, 0x32, 0x2e, 0x32, 0x00 };
            if (hashAlgorithmName.Name == HashAlgorithmName.SHA512.Name)
                return new byte[] { 0x32, 0x2e, 0x31, 0x36, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x2e, 0x31, 0x30, 0x31, 0x2e, 0x33, 0x2e, 0x34, 0x2e, 0x32, 0x2e, 0x33, 0x00 };
            throw new NotSupportedException("The algorithm specified is not supported.");
        }
    }
}
