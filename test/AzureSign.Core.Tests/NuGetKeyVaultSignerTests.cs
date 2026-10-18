using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Packaging;
using NuGet.Packaging.Signing;
using Xunit;

namespace AzureSign.Core.Tests
{
    public class NuGetKeyVaultSignerTests : IDisposable
    {
        private readonly DirectoryInfo _scratchDirectory;

        public NuGetKeyVaultSignerTests()
        {
            var directory = Path.Join(Path.GetTempPath(), "AzureSign.Core.Tests.NuGet", Guid.NewGuid().ToString("N"));
            _scratchDirectory = Directory.CreateDirectory(directory);
        }

        [Theory]
        [MemberData(nameof(RsaCertificatesAndDigests))]
        public async Task ShouldSignNuGetPackage(string certificate, string digest)
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(certificate, "test", X509KeyStorageFlags.EphemeralKeySet);
            using var signer = new NuGetKeyVaultSigner(signingCert.GetRSAPrivateKey()!, signingCert, new HashAlgorithmName(digest), TimeStampConfiguration.None);
            var package = CreatePackage();
            var originalEntries = GetEntries(package);
            Assert.False(NuGetKeyVaultSigner.IsSigned(package));

            var result = signer.SignFile(package, cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal(0, result);
            Assert.True(NuGetKeyVaultSigner.IsSigned(package));
            await AssertValidAuthorSignature(package, signingCert, originalEntries);
        }

        [Theory]
        [MemberData(nameof(RsaCertificates))]
        public async Task ShouldReplaceExistingSignature(string certificate)
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(certificate, "test", X509KeyStorageFlags.EphemeralKeySet);
            using var signer = new NuGetKeyVaultSigner(signingCert.GetRSAPrivateKey()!, signingCert, HashAlgorithmName.SHA256, TimeStampConfiguration.None);
            var package = CreatePackage();
            var originalEntries = GetEntries(package);

            Assert.Equal(0, signer.SignFile(package, cancellationToken: TestContext.Current.CancellationToken));
            Assert.Equal(0, signer.SignFile(package, cancellationToken: TestContext.Current.CancellationToken));

            await AssertValidAuthorSignature(package, signingCert, originalEntries);
        }

        [Theory]
        [MemberData(nameof(RsaCertificates))]
        public async Task ShouldSignNuGetPackageWithTimestamp(string certificate)
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(certificate, "test", X509KeyStorageFlags.EphemeralKeySet);
            var timestampConfig = new TimeStampConfiguration("http://timestamp.digicert.com", HashAlgorithmName.SHA256, TimeStampType.RFC3161);
            using var signer = new NuGetKeyVaultSigner(signingCert.GetRSAPrivateKey()!, signingCert, HashAlgorithmName.SHA256, timestampConfig);
            var package = CreatePackage();
            var originalEntries = GetEntries(package);

            Assert.Equal(0, signer.SignFile(package, cancellationToken: TestContext.Current.CancellationToken));

            var signature = await AssertValidAuthorSignature(package, signingCert, originalEntries);
            var timestamp = Assert.Single(signature.Timestamps);
            Assert.InRange(timestamp.GeneralizedTime, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1));
        }

        [Fact]
        public void ShouldSignSymbolPackage()
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("signcerts", "rsa-2048.pfx"), "test", X509KeyStorageFlags.EphemeralKeySet);
            using var signer = new NuGetKeyVaultSigner(signingCert.GetRSAPrivateKey()!, signingCert, HashAlgorithmName.SHA256, TimeStampConfiguration.None);
            var package = CreatePackage(".snupkg");

            Assert.True(NuGetKeyVaultSigner.IsNuGetPackage(package));
            Assert.Equal(0, signer.SignFile(package, cancellationToken: TestContext.Current.CancellationToken));
            Assert.True(NuGetKeyVaultSigner.IsSigned(package));
        }

        [Fact]
        public void ShouldRejectSha1FileDigest()
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("signcerts", "rsa-2048.pfx"), "test", X509KeyStorageFlags.EphemeralKeySet);
            Assert.Throws<ArgumentException>(() => new NuGetKeyVaultSigner(signingCert.GetRSAPrivateKey()!, signingCert, HashAlgorithmName.SHA1, TimeStampConfiguration.None));
        }

        [Fact]
        public void ShouldRejectAuthenticodeTimestamp()
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("signcerts", "rsa-2048.pfx"), "test", X509KeyStorageFlags.EphemeralKeySet);
            var timestampConfig = new TimeStampConfiguration("http://timestamp.digicert.com", default, TimeStampType.Authenticode);
            Assert.Throws<ArgumentException>(() => new NuGetKeyVaultSigner(signingCert.GetRSAPrivateKey()!, signingCert, HashAlgorithmName.SHA256, timestampConfig));
        }

        [Fact]
        public void ShouldRejectECDsaKey()
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("signcerts", "ecdsa-nist-p256.pfx"), "test", X509KeyStorageFlags.EphemeralKeySet);
            Assert.Throws<ArgumentException>(() => new NuGetKeyVaultSigner(signingCert.GetECDsaPrivateKey()!, signingCert, HashAlgorithmName.SHA256, TimeStampConfiguration.None));
        }

        [Theory]
        [MemberData(nameof(RsaCertificatesAndDigests))]
        public async Task ShouldPassNuGetSignatureVerification(string certificate, string digest)
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(certificate, "test", X509KeyStorageFlags.EphemeralKeySet);
            using var signer = new NuGetKeyVaultSigner(signingCert.GetRSAPrivateKey()!, signingCert, new HashAlgorithmName(digest), TimeStampConfiguration.None);
            var package = CreatePackage();

            Assert.Equal(0, signer.SignFile(package, cancellationToken: TestContext.Current.CancellationToken));

            await AssertPassesNuGetVerification(package);
        }

        [Fact]
        public void ShouldNotReportUnreadablePackageAsSigned()
        {
            var package = CreatePackage();

            using (File.Open(package, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                Assert.False(NuGetKeyVaultSigner.IsSigned(package));
            }
        }

        [Fact]
        public async Task ShouldDetectSignatureWithUtf8Flag()
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("signcerts", "rsa-2048.pfx"), "test", X509KeyStorageFlags.EphemeralKeySet);
            using var signer = new NuGetKeyVaultSigner(signingCert.GetRSAPrivateKey()!, signingCert, HashAlgorithmName.SHA256, TimeStampConfiguration.None);
            var package = CreatePackage();
            var originalEntries = GetEntries(package);
            Assert.Equal(0, signer.SignFile(package, cancellationToken: TestContext.Current.CancellationToken));

            SetUtf8FlagOnSignatureEntry(package);

            Assert.True(NuGetKeyVaultSigner.IsSigned(package));
            Assert.Equal(0, signer.SignFile(package, cancellationToken: TestContext.Current.CancellationToken));
            await AssertValidAuthorSignature(package, signingCert, originalEntries);
        }

        [Fact]
        public async Task ShouldPreserveArchiveComment()
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("signcerts", "rsa-2048.pfx"), "test", X509KeyStorageFlags.EphemeralKeySet);
            using var signer = new NuGetKeyVaultSigner(signingCert.GetRSAPrivateKey()!, signingCert, HashAlgorithmName.SHA256, TimeStampConfiguration.None);
            var package = CreatePackage(comment: "Archive comment");
            var originalEntries = GetEntries(package);

            Assert.Equal(0, signer.SignFile(package, cancellationToken: TestContext.Current.CancellationToken));

            await AssertValidAuthorSignature(package, signingCert, originalEntries);
            using var archive = ZipFile.OpenRead(package);
            Assert.Equal("Archive comment", archive.Comment);
        }

        [Fact]
        public void ShouldFailOnReadOnlyPackageWithoutChangingIt()
        {
            var signingCert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine("signcerts", "rsa-2048.pfx"), "test", X509KeyStorageFlags.EphemeralKeySet);
            using var signer = new NuGetKeyVaultSigner(signingCert.GetRSAPrivateKey()!, signingCert, HashAlgorithmName.SHA256, TimeStampConfiguration.None);
            var package = CreatePackage();
            var originalBytes = File.ReadAllBytes(package);
            File.SetAttributes(package, FileAttributes.ReadOnly);

            try
            {
                Assert.NotEqual(0, signer.SignFile(package, cancellationToken: TestContext.Current.CancellationToken));
                Assert.Equal(originalBytes, File.ReadAllBytes(package));
            }
            finally
            {
                File.SetAttributes(package, FileAttributes.Normal);
            }
        }

        [Theory]
        [InlineData("package.nupkg", true)]
        [InlineData("package.NUPKG", true)]
        [InlineData("package.snupkg", true)]
        [InlineData("package.zip", false)]
        [InlineData("package.exe", false)]
        public void ShouldDetectNuGetPackageExtensions(string path, bool expected)
        {
            Assert.Equal(expected, NuGetKeyVaultSigner.IsNuGetPackage(path));
        }

        private static async Task<PrimarySignature> AssertValidAuthorSignature(string package, X509Certificate2 signingCert, Dictionary<string, byte[]> originalEntries)
        {
            using (var reader = new PackageArchiveReader(package))
            {
                Assert.True(await reader.IsSignedAsync(TestContext.Current.CancellationToken));
                var signature = await reader.GetPrimarySignatureAsync(TestContext.Current.CancellationToken);
                Assert.NotNull(signature);
                Assert.Equal(SignatureType.Author, signature.Type);
                Assert.Equal(signingCert.Thumbprint, signature.SignerInfo.Certificate!.Thumbprint);

                // Throws if the package content does not match the hash in the signature.
                await reader.ValidateIntegrityAsync(signature.SignatureContent, TestContext.Current.CancellationToken);

                var cms = new SignedCms();
                cms.Decode(signature.GetBytes());
                cms.CheckSignature(verifySignatureOnly: true);

                // The original entries are intact and the only new entry is the signature file.
                var entries = GetEntries(package);
                Assert.Equal(originalEntries.Count + 1, entries.Count);
                Assert.Contains(".signature.p7s", entries.Keys);
                foreach (var (name, content) in originalEntries)
                {
                    Assert.Equal(content, entries[name]);
                }

                return signature;
            }
        }

        private static async Task AssertPassesNuGetVerification(string package)
        {
            // The test certificates are not trusted, so untrusted roots are allowed. Every other check is an error.
            var settings = new SignedPackageVerifierSettings(
                allowUnsigned: false,
                allowIllegal: false,
                allowUntrusted: true,
                allowIgnoreTimestamp: true,
                allowMultipleTimestamps: false,
                allowNoTimestamp: true,
                allowUnknownRevocation: true,
                reportUnknownRevocation: false,
                verificationTarget: VerificationTarget.All,
                signaturePlacement: SignaturePlacement.Any,
                repositoryCountersignatureVerificationBehavior: SignatureVerificationBehavior.IfExistsAndIsNecessary,
                revocationMode: NuGet.Common.RevocationMode.Offline);
            var verifier = new PackageSignatureVerifier(new ISignatureVerificationProvider[]
            {
                new IntegrityVerificationProvider(),
                new SignatureTrustAndValidityVerificationProvider(),
            });

            using var reader = new PackageArchiveReader(package);
            var result = await verifier.VerifySignaturesAsync(reader, settings, TestContext.Current.CancellationToken);
            var errors = result.Results
                .SelectMany(r => r.Issues)
                .Where(issue => issue.Level == NuGet.Common.LogLevel.Error)
                .Select(issue => $"{issue.Code}: {issue.Message}");

            Assert.True(result.IsValid, string.Join(Environment.NewLine, errors));
        }

        private static void SetUtf8FlagOnSignatureEntry(string package)
        {
            const int LocalFileHeaderSignature = 0x04034b50;
            const int CentralDirectoryHeaderSignature = 0x02014b50;
            var bytes = File.ReadAllBytes(package);
            var name = Encoding.ASCII.GetBytes(".signature.p7s");
            var updated = 0;
            var start = 0;
            int found;

            while ((found = bytes.AsSpan(start).IndexOf(name)) >= 0)
            {
                var i = start + found;
                start = i + 1;

                // The file name follows the fixed part of the local file header (30 bytes) or central directory header (46 bytes).
                if (i >= 30 && BitConverter.ToInt32(bytes, i - 30) == LocalFileHeaderSignature)
                {
                    bytes[i - 30 + 7] |= 0x08;
                    updated++;
                }
                else if (i >= 46 && BitConverter.ToInt32(bytes, i - 46) == CentralDirectoryHeaderSignature)
                {
                    bytes[i - 46 + 9] |= 0x08;
                    updated++;
                }
            }

            Assert.Equal(2, updated);
            File.WriteAllBytes(package, bytes);
        }

        private static Dictionary<string, byte[]> GetEntries(string package)
        {
            using var archive = ZipFile.OpenRead(package);
            var entries = new Dictionary<string, byte[]>();

            foreach (var entry in archive.Entries)
            {
                using var stream = entry.Open();
                using var buffer = new MemoryStream();
                stream.CopyTo(buffer);
                entries.Add(entry.FullName, buffer.ToArray());
            }

            return entries;
        }

        private string CreatePackage(string extension = ".nupkg", string comment = null)
        {
            var path = Path.Combine(_scratchDirectory.FullName, $"{Guid.NewGuid():N}{extension}");

            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                if (comment is not null)
                {
                    archive.Comment = comment;
                }

                AddEntry(archive, "Test.Package.nuspec", """
                    <?xml version="1.0" encoding="utf-8"?>
                    <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                      <metadata>
                        <id>Test.Package</id>
                        <version>1.0.0</version>
                        <authors>Test</authors>
                        <description>Test package.</description>
                      </metadata>
                    </package>
                    """);
                AddEntry(archive, "lib/net8.0/Test.Package.dll", File.ReadAllText("signtarget.exe", Encoding.Latin1));
                AddEntry(archive, "[Content_Types].xml", "<Types />");
            }

            return path;

            static void AddEntry(ZipArchive archive, string name, string content)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
                using var writer = new StreamWriter(entry.Open(), Encoding.Latin1);
                writer.Write(content);
            }
        }

        public void Dispose()
        {
            _scratchDirectory.Delete(true);
        }

        public static IEnumerable<object[]> RsaCertificates =>
            Directory.EnumerateFiles("signcerts", "rsa-*.pfx").Select(file => new object[] { file });

        public static IEnumerable<object[]> RsaCertificatesAndDigests
        {
            get
            {
                foreach (var file in Directory.EnumerateFiles("signcerts", "rsa-*.pfx"))
                {
                    foreach (var digest in new[] { "SHA256", "SHA384", "SHA512" })
                    {
                        yield return new object[] { file, digest };
                    }
                }
            }
        }
    }
}
