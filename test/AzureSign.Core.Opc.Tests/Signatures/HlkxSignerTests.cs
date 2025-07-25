using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AzureSign.Core.Opc.Containers;
using AzureSign.Core.Opc.Signatures;
using AzureSign.Core.Opc.Tests.TestData;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AzureSign.Core.Opc.Tests.Signatures;

public class HlkxSignerTests : IDisposable
{
    private readonly string _tempFile;
    private readonly X509Certificate2 _testCertificate;
    private readonly RSA _testRsa;

    public HlkxSignerTests()
    {
        _tempFile = Path.GetTempFileName();
        SyntheticHlkxGenerator.CreateMinimalHlkx(_tempFile);
        
        // Create a test certificate and RSA key pair
        _testRsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Test Certificate for HLKX Signing",
            _testRsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        _testCertificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
    }

    [Fact]
    public async Task SignFileAsync_ValidHlkxFile_ShouldSucceed()
    {
        // Arrange
        var signer = new HlkxSigner();

        // Act
        var result = await signer.SignFileAsync(
            _tempFile,
            _testRsa,
            _testCertificate,
            HashAlgorithmName.SHA256,
            NullLogger.Instance);

        // Assert
        result.Should().Be(0); // S_OK
    }

    [Fact]
    public void Container_CanLoadSyntheticFile()
    {
        // Test if the basic container loading works
        using var container = HlkxContainer.Open(_tempFile);
        var parts = container.GetParts().ToList();
        
        parts.Should().NotBeEmpty();
        parts.Should().Contain(p => p.Path == "/[Content_Types].xml");
        parts.Should().Contain(p => p.Path == "/_rels/.rels");
    }

    [Fact]
    public void ManifestBuilder_CanCreateBasicManifest()
    {
        // Test if manifest creation works with synthetic data
        using var container = HlkxContainer.Open(_tempFile);
        var parts = container.GetParts()
            .Where(p => p.Path.StartsWith("/hck/data/"))
            .ToList();
        var relationships = container.GetRelationships().ToList();

        var manifestBuilder = new OpcManifestBuilder(HashAlgorithmName.SHA256);
        
        // This should not throw an exception
        var manifest = manifestBuilder.CreateManifest(parts, relationships);
        
        manifest.Should().NotBeEmpty();
        manifest.Should().Contain("Manifest");
    }

    [Fact]
    public async Task SignFileAsync_NonExistentFile_ShouldFail()
    {
        // Arrange
        var signer = new HlkxSigner();
        var nonExistentFile = Path.Combine(Path.GetTempPath(), "nonexistent.hlkx");

        // Act
        var result = await signer.SignFileAsync(
            nonExistentFile,
            _testRsa,
            _testCertificate,
            HashAlgorithmName.SHA256,
            NullLogger.Instance);

        // Assert
        result.Should().NotBe(0); // Should fail
    }

    [Fact]
    public async Task VerifyFileAsync_UnsignedFile_ShouldReturnFalse()
    {
        // Arrange
        var signer = new HlkxSigner();

        // Act
        var result = await signer.VerifyFileAsync(_tempFile, NullLogger.Instance);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyFileAsync_SignedFile_ShouldReturnTrue()
    {
        // Arrange
        var signer = new HlkxSigner();
        
        // First sign the file
        await signer.SignFileAsync(
            _tempFile,
            _testRsa,
            _testCertificate,
            HashAlgorithmName.SHA256,
            NullLogger.Instance);

        // Act
        var result = await signer.VerifyFileAsync(_tempFile, NullLogger.Instance);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyFileAsync_PreSignedSyntheticFile_ShouldReturnTrue()
    {
        // Arrange
        var preSignedFile = Path.GetTempFileName();
        SyntheticHlkxGenerator.CreatePreSignedHlkx(preSignedFile);
        var signer = new HlkxSigner();

        try
        {
            // Act
            var result = await signer.VerifyFileAsync(preSignedFile, NullLogger.Instance);

            // Assert
            result.Should().BeTrue();
        }
        finally
        {
            if (File.Exists(preSignedFile))
                File.Delete(preSignedFile);
        }
    }

    [Fact]
    public async Task SignFileAsync_InvalidHlkxFile_ShouldFail()
    {
        // Arrange
        var invalidFile = Path.GetTempFileName();
        SyntheticHlkxGenerator.CreateInvalidHlkx(invalidFile);
        var signer = new HlkxSigner();

        try
        {
            // Act
            var result = await signer.SignFileAsync(
                invalidFile,
                _testRsa,
                _testCertificate,
                HashAlgorithmName.SHA256,
                NullLogger.Instance);

            // Assert
            result.Should().NotBe(0); // Should fail
        }
        finally
        {
            if (File.Exists(invalidFile))
                File.Delete(invalidFile);
        }
    }

    [Theory]
    [InlineData("SHA1")]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public async Task SignFileAsync_DifferentHashAlgorithms_ShouldSucceed(string algorithmName)
    {
        // Arrange
        var signer = new HlkxSigner();
        var hashAlgorithm = new HashAlgorithmName(algorithmName);

        // Act
        var result = await signer.SignFileAsync(
            _tempFile,
            _testRsa,
            _testCertificate,
            hashAlgorithm,
            NullLogger.Instance);

        // Assert
        result.Should().Be(0); // S_OK
    }

    public void Dispose()
    {
        if (File.Exists(_tempFile))
        {
            File.Delete(_tempFile);
        }
        
        _testCertificate?.Dispose();
        _testRsa?.Dispose();
    }
}