using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace AzureSign.Core.Tests
{
    public class AuthenticodeKeyVaultSignerTests : IDisposable
    {
        private readonly DirectoryInfo _scratchDirectory;

        public AuthenticodeKeyVaultSignerTests()
        {
            var directory = Path.Join(Path.GetTempPath(), "AzureSign.Core.Tests");
            _scratchDirectory = Directory.CreateDirectory(directory);
        }


        [Theory]
        [MemberData(nameof(RsaCertificates))]
        public void ShouldSignExeWithRSASigningCertificates_Sha1FileDigest(string certificate)
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(certificate, "test", X509KeyStorageFlags.EphemeralKeySet);
            var signer = new AuthenticodeKeyVaultSigner(signingCert.GetRSAPrivateKey(), signingCert, HashAlgorithmName.SHA1, TimeStampConfiguration.None);
            var fileToSign = GetFileToSign();
            var result = signer.SignFile(fileToSign, null, null, null);
            Assert.Equal(0, result);
            if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 20348))
            {
                result = signer.SignFile(fileToSign, null, null, null, appendSignature: true);
                Assert.Equal(0, result);
                result = signer.SignFile(fileToSign, null, null, null, appendSignature: false);
                Assert.Equal(0, result);
            }
        }

        [Theory]
        [MemberData(nameof(RsaCertificates))]
        public void ShouldSignExeWithRSASigningCertificates_Sha256FileDigest(string certificate)
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(certificate, "test", X509KeyStorageFlags.EphemeralKeySet);
            var signer = new AuthenticodeKeyVaultSigner(signingCert.GetRSAPrivateKey(), signingCert, HashAlgorithmName.SHA256, TimeStampConfiguration.None);
            var fileToSign = GetFileToSign();
            var result = signer.SignFile(fileToSign, null, null, null);
            Assert.Equal(0, result);
            if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 20348))
            {
                result = signer.SignFile(fileToSign, null, null, null, appendSignature: true);
                Assert.Equal(0, result);
                result = signer.SignFile(fileToSign, null, null, null, appendSignature: false);
                Assert.Equal(0, result);
            }
        }


        [Theory]
        [MemberData(nameof(ECDsaCertificates))]
        public void ShouldSignExeWithECDsaSigningCertificates_Sha256FileDigest(string certificate)
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(certificate, "test", X509KeyStorageFlags.EphemeralKeySet);
            var signer = new AuthenticodeKeyVaultSigner(signingCert.GetECDsaPrivateKey(), signingCert, HashAlgorithmName.SHA256, TimeStampConfiguration.None);
            var fileToSign = GetFileToSign();
            var result = signer.SignFile(fileToSign, null, null, null);
            Assert.Equal(0, result);
            if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 20348))
            {
                result = signer.SignFile(fileToSign, null, null, null, appendSignature: true);
                Assert.Equal(0, result);
                result = signer.SignFile(fileToSign, null, null, null, appendSignature: false);
                Assert.Equal(0, result);
            }
        }

        [Theory]
        [MemberData(nameof(ECDsaCertificates))]
        public void ShouldSignExeWithECDsaSigningCertificates_Sha256FileDigest_WithTimestamps(string certificate)
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(certificate, "test", X509KeyStorageFlags.EphemeralKeySet);
            var timestampConfig = new TimeStampConfiguration("http://timestamp.digicert.com", HashAlgorithmName.SHA256, TimeStampType.RFC3161);
            var signer = new AuthenticodeKeyVaultSigner(signingCert.GetECDsaPrivateKey(), signingCert, HashAlgorithmName.SHA256, timestampConfig);
            var fileToSign = GetFileToSign();
            var result = signer.SignFile(fileToSign, null, null, null);
            Assert.Equal(0, result);
            if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 20348))
            {
                result = signer.SignFile(fileToSign, null, null, null, appendSignature: true);
                Assert.Equal(0, result);
                result = signer.SignFile(fileToSign, null, null, null, appendSignature: false);
                Assert.Equal(0, result);
            }
        }


        [Theory]
        [MemberData(nameof(RsaCertificates))]
        public void ShouldSignExeWithRSASigningCertificates_Sha256FileDigest_WithTimestamps(string certificate)
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(certificate, "test", X509KeyStorageFlags.EphemeralKeySet);
            var timestampConfig = new TimeStampConfiguration("http://timestamp.digicert.com", HashAlgorithmName.SHA256, TimeStampType.RFC3161);
            var signer = new AuthenticodeKeyVaultSigner(signingCert.GetRSAPrivateKey(), signingCert, HashAlgorithmName.SHA256, timestampConfig);
            var fileToSign = GetFileToSign();
            var result = signer.SignFile(fileToSign, null, null, null);
            Assert.Equal(0, result);
            if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 20348))
            {
                result = signer.SignFile(fileToSign, null, null, null, appendSignature: true);
                Assert.Equal(0, result);
                result = signer.SignFile(fileToSign, null, null, null, appendSignature: false);
                Assert.Equal(0, result);
            }
        }

        private string GetFileToSign()
        {
            var guid = Guid.NewGuid();
            var path = Path.Combine(_scratchDirectory.FullName, $"{guid}.exe");
            File.Copy("signtarget.exe", path);
            return path;
        }

        public void Dispose()
        {
           _scratchDirectory.Delete(true);
        }

        public static IEnumerable<object[]> RsaCertificates
        {
            get
            {
                var root = "signcerts";
                foreach (var file in Directory.EnumerateFiles(root, "rsa-*.pfx"))
                {
                    yield return new object[] { file };
                }
            }
        }

        public static IEnumerable<object[]> ECDsaCertificates
        {
            get
            {
                var root = "signcerts";
                foreach (var file in Directory.EnumerateFiles(root, "ecdsa-*.pfx"))
                {
                    yield return new object[] { file };
                }
            }
        }
    }
}
