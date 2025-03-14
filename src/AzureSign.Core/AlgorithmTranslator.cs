using System;
using System.Security.Cryptography;

namespace AzureSign.Core
{
    internal static class AlgorithmTranslator
    {
        public static uint HashAlgorithmToAlgId(HashAlgorithmName hashAlgorithmName)
        {
            return hashAlgorithmName.Name switch
            {
                nameof(HashAlgorithmName.SHA1) => 0x00008004,
                nameof(HashAlgorithmName.SHA256) => 0x0000800c,
                nameof(HashAlgorithmName.SHA384) => 0x0000800d,
                nameof(HashAlgorithmName.SHA512) => 0x0000800e,
                _ => throw new NotSupportedException("The algorithm specified is not supported."),
            };
        }

        public static ReadOnlySpan<byte> HashAlgorithmToOidAsciiTerminated(HashAlgorithmName hashAlgorithmName)
        {
            return hashAlgorithmName.Name switch
            {
                nameof(HashAlgorithmName.SHA1) => "1.3.14.3.2.26\0"u8,
                nameof(HashAlgorithmName.SHA256) => "2.16.840.1.101.3.4.2.1\0"u8,
                nameof(HashAlgorithmName.SHA384) => "2.16.840.1.101.3.4.2.2\0"u8,
                nameof(HashAlgorithmName.SHA512) => "2.16.840.1.101.3.4.2.3\0"u8,
                _ => throw new NotSupportedException("The algorithm specified is not supported."),
            };
        }
    }
}
