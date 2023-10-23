using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace AzureSign.Core.Tests
{
    public class AlgorithmTranslatorTests
    {
        [Theory]
        [MemberData(nameof(NameToAlgIdData))]
        public void ShouldTranslateNameToCAPIAlgId(HashAlgorithmName name, uint algId)
        {
            Assert.Equal(algId, AlgorithmTranslator.HashAlgorithmToAlgId(name));
        }

        [Theory]
        [MemberData(nameof(NameToAsciiNullOid))]
        public void ShouldTranslateNameToAsciiEncodedNullTerminatedOID(HashAlgorithmName name, string oid)
        {
            Span<byte> expectedBytes = stackalloc byte[oid.Length + 1];
            expectedBytes.Fill(0);
            Encoding.ASCII.GetBytes(oid, expectedBytes);
            var actualBytes = AlgorithmTranslator.HashAlgorithmToOidAsciiTerminated(name);
            Assert.True(expectedBytes.SequenceEqual(Encoding.ASCII.GetBytes(actualBytes)), "ExpectedBytes do not equal actual bytes.");
        }

        [Fact]
        public void ShouldThrowNotSupportExceptionForUnknownAlgId()
        {
            Assert.Throws<NotSupportedException>(() => {
                AlgorithmTranslator.HashAlgorithmToAlgId(default);
            });
        }

        [Fact]
        public void ShouldThrowNotSupportExceptionForUnknownOID()
        {
            Assert.Throws<NotSupportedException>(() => {
                AlgorithmTranslator.HashAlgorithmToOidAsciiTerminated(default);
            });
        }

        public static IEnumerable<object[]> NameToAsciiNullOid
        {
            get
            {
                yield return new object[] { HashAlgorithmName.SHA1, "1.3.14.3.2.26" };
                yield return new object[] { HashAlgorithmName.SHA256, "2.16.840.1.101.3.4.2.1" };
                yield return new object[] { HashAlgorithmName.SHA384, "2.16.840.1.101.3.4.2.2" };
                yield return new object[] { HashAlgorithmName.SHA512, "2.16.840.1.101.3.4.2.3" };
            }
        }

        public static IEnumerable<object[]> NameToAlgIdData
        {
            get
            {
                yield return new object[] { HashAlgorithmName.SHA1, 0x00008004 };
                yield return new object[] { HashAlgorithmName.SHA256, 0x0000800c };
                yield return new object[] { HashAlgorithmName.SHA384, 0x0000800d };
                yield return new object[] { HashAlgorithmName.SHA512, 0x0000800e };
            }
        }
            
    }
}
