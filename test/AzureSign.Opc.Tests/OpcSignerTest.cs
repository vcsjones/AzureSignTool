using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AzureSign.Opc.Tests.TestData;

namespace AzureSign.Opc.Tests;

public sealed class OpcSignerTest : IDisposable
{
    private readonly DirectoryInfo _scratchDirectory;

    public OpcSignerTest()
    {
        var directory = Path.Join(Path.GetTempPath(), GetType().FullName);
        _scratchDirectory = Directory.CreateDirectory(directory);
    }

    [Theory]
    [InlineData(VerificationOptions.Default, VerificationStatus.NotSigned)]
    [InlineData(VerificationOptions.VerifySignatureValidity, VerificationStatus.NotSigned)]
    [InlineData(VerificationOptions.VerifyProviderCertificateMatch, VerificationStatus.NotSigned)]
    public async Task Given_unsigned_hlkx_file_VerifySignatures_returns_expected_result(
        VerificationOptions verificationOptions,
        VerificationStatus expectedStatus
    )
    {
        var ct = TestContext.Current.CancellationToken;
        var unsignedHlkx = GetTestFile("BasicUnsignedHlkPackage");
        var testCertificate = GetTestCertificate(HashAlgorithmName.SHA256, 2048);

        var opcSigner = new OpcSigner(
            new X509CertificateProvider(testCertificate),
            cryptoServiceProvider: null,
            digestHashAlgorithm: HashAlgorithmName.SHA256
        );
        var verificationResult = await opcSigner.VerifySignatures(
            unsignedHlkx,
            verificationOptions,
            ct: ct
        );

        verificationResult.Status.Should().Be(expectedStatus);
    }

    [Theory]
    [InlineData(VerificationOptions.Default, VerificationStatus.UnmatchedPackagePart)]
    [InlineData(VerificationOptions.VerifySignatureValidity, VerificationStatus.Success)]
    [InlineData(
        VerificationOptions.VerifyProviderCertificateMatch,
        VerificationStatus.UnmatchedPackagePart
    )]
    public async Task Given_signed_hlkx_file_VerifySignatures_returns_expected_result(
        VerificationOptions verificationOptions,
        VerificationStatus expectedStatus
    )
    {
        var ct = TestContext.Current.CancellationToken;
        var unsignedHlkx = GetTestFile("BasicPresignedHlkPackage");
        var testCertificate = GetTestCertificate(HashAlgorithmName.SHA256, 2048);

        var opcSigner = new OpcSigner(
            new X509CertificateProvider(testCertificate),
            cryptoServiceProvider: null,
            digestHashAlgorithm: HashAlgorithmName.SHA256
        );
        var verificationResult = await opcSigner.VerifySignatures(
            unsignedHlkx,
            verificationOptions,
            ct: ct
        );

        verificationResult.Status.Should().Be(expectedStatus);
    }

    [Theory]
    [ClassData(typeof(CertificateTestData))]
    public async Task Given_unsigned_hlkx_file_it_signs_using_a_certificate_with_private_key(
        HashAlgorithmName hashAlgorithm,
        int rsaKeySizeInBits
    )
    {
        var ct = TestContext.Current.CancellationToken;
        var testFile = GetTestFile("BasicUnsignedHlkPackage");
        var testCertificate = GetTestCertificate(hashAlgorithm, rsaKeySizeInBits);

        var opcSigner = new OpcSigner(
            new X509CertificateProvider(testCertificate),
            cryptoServiceProvider: null,
            digestHashAlgorithm: hashAlgorithm
        );

        _ = await opcSigner.Sign(testFile, ct);

        var result = await opcSigner.VerifySignatures(testFile, ct: ct);
        result.ThrowIfFailed();
    }

    [Theory]
    [ClassData(typeof(CertificateTestData))]
    public async Task Given_unsigned_hlkx_file_it_signs_using_X509_certificate_and_separate_RSA_private_key(
        HashAlgorithmName hashAlgorithm,
        int rsaKeySizeInBits
    )
    {
        var ct = TestContext.Current.CancellationToken;
        var testFile = GetTestFile("BasicUnsignedHlkPackage");
        var testCertificate = GetTestCertificate(hashAlgorithm, rsaKeySizeInBits);

        var publicCertificate = new X509Certificate2(testCertificate.Export(X509ContentType.Cert));
        publicCertificate.GetRSAPrivateKey().Should().BeNull();

        var rsa = testCertificate.GetRSAPrivateKey();
        rsa.Should().NotBeNull();

        var opcSigner = new OpcSigner(
            new X509CertificateProvider(publicCertificate),
            new RsaCryptoServiceProvider(rsa!),
            hashAlgorithm
        );

        _ = await opcSigner.Sign(testFile, ct);

        var result = await opcSigner.VerifySignatures(testFile, ct: ct);
        result.ThrowIfFailed();
    }

    [Theory]
    [ClassData(typeof(CertificateTestData))]
    public async Task Given_presigned_hlkx_file_it_signs_using_X509_certificate_and_separate_RSA_private_key(
        HashAlgorithmName hashAlgorithm,
        int rsaKeySizeInBits
    )
    {
        var ct = TestContext.Current.CancellationToken;
        var testFile = GetTestFile("BasicPresignedHlkPackage");
        var testCertificate = GetTestCertificate(hashAlgorithm, rsaKeySizeInBits);

        var publicCertificate = new X509Certificate2(testCertificate.Export(X509ContentType.Cert));
        publicCertificate.GetRSAPrivateKey().Should().BeNull();

        var rsa = testCertificate.GetRSAPrivateKey();
        rsa.Should().NotBeNull();

        var opcSigner = new OpcSigner(
            new X509CertificateProvider(publicCertificate),
            new RsaCryptoServiceProvider(rsa!),
            hashAlgorithm
        );

        _ = await opcSigner.Sign(testFile, ct);
        var result = await opcSigner.VerifySignatures(testFile, ct: ct);
        result.ThrowIfFailed();
    }

    private static X509Certificate2 GetTestCertificate(
        HashAlgorithmName hashAlgorithm,
        int rsaKeySizeInBits
    )
    {
        return X509CertificateProvider.CreateSelfSignedRsa(
            $"CN={typeof(OpcSignerTest).FullName}.{hashAlgorithm}_{rsaKeySizeInBits}",
            hashAlgorithm,
            rsaKeySizeInBits,
            365
        );
    }

    private string GetTestFile(string assetName, string extension = "hlkx")
    {
        var guid = Guid.NewGuid();
        var assetPath = Path.Combine("TestAssets", $"{assetName}.{extension}");
        var outputPath = Path.Combine(
            _scratchDirectory.FullName,
            $"{assetName}_{guid}.{extension}"
        );
        File.Copy(assetPath, outputPath);
        return outputPath;
    }

    public void Dispose()
    {
        _scratchDirectory.Delete(true);
    }
}
