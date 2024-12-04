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
    [InlineData("")]
    [InlineData("Non_Existent_Hardware_Lab_Kit_File.hlkx")]
    public async Task Given_an_invalid_hlkx_path_Verify_returns_Status_IoError(string filePath)
    {
        using var certificateProvider = GetTestCertificateProvider(HashAlgorithmName.SHA256, 2048);

        var opcSigner = new OpcSigner(
            certificateProvider,
            cryptoServiceProvider: null,
            digestHashAlgorithm: HashAlgorithmName.SHA256
        );
        var verificationResult = await opcSigner.Verify(filePath, ct: CancellationToken.None);
        verificationResult.Status.Should().Be(OpcVerifyStatus.IoError);
    }

    [Fact]
    public async Task Given_invalid_hlkx_file_Verify_returns_Status_InvalidData()
    {
        var invalidHlkx = GetTestFile("InvalidHlkxPackage");
        using var certificateProvider = GetTestCertificateProvider(HashAlgorithmName.SHA256, 2048);

        var opcSigner = new OpcSigner(
            certificateProvider,
            cryptoServiceProvider: null,
            digestHashAlgorithm: HashAlgorithmName.SHA256
        );
        var verificationResult = await opcSigner.Verify(invalidHlkx, ct: CancellationToken.None);
        verificationResult.Status.Should().Be(OpcVerifyStatus.InvalidData);
    }

    [Theory]
    [InlineData(OpcVerifyOptions.Default, OpcVerifyStatus.NotSigned)]
    [InlineData(OpcVerifyOptions.VerifySignatureValidity, OpcVerifyStatus.NotSigned)]
    [InlineData(OpcVerifyOptions.VerifyProviderCertificateMatch, OpcVerifyStatus.NotSigned)]
    public async Task Given_unsigned_hlkx_file_Verify_returns_expected_result(
        OpcVerifyOptions verificationOptions,
        OpcVerifyStatus expectedStatus
    )
    {
        var ct = TestContext.Current.CancellationToken;
        var unsignedHlkx = GetTestFile("BasicUnsignedHlkPackage");
        using var certificateProvider = GetTestCertificateProvider(HashAlgorithmName.SHA256, 2048);

        var opcSigner = new OpcSigner(
            certificateProvider,
            cryptoServiceProvider: null,
            digestHashAlgorithm: HashAlgorithmName.SHA256
        );
        var verificationResult = await opcSigner.Verify(unsignedHlkx, verificationOptions, ct: ct);

        verificationResult.Status.Should().Be(expectedStatus);
    }

    [Theory]
    [InlineData(OpcVerifyOptions.Default, OpcVerifyStatus.UnmatchedPackagePart)]
    [InlineData(OpcVerifyOptions.VerifySignatureValidity, OpcVerifyStatus.Success)]
    [InlineData(
        OpcVerifyOptions.VerifyProviderCertificateMatch,
        OpcVerifyStatus.UnmatchedPackagePart
    )]
    public async Task Given_signed_hlkx_file_Verify_returns_expected_result(
        OpcVerifyOptions verificationOptions,
        OpcVerifyStatus expectedStatus
    )
    {
        var ct = TestContext.Current.CancellationToken;
        var unsignedHlkx = GetTestFile("BasicPresignedHlkPackage");
        using var certificateProvider = GetTestCertificateProvider(HashAlgorithmName.SHA256, 2048);

        var opcSigner = new OpcSigner(
            certificateProvider,
            cryptoServiceProvider: null,
            digestHashAlgorithm: HashAlgorithmName.SHA256
        );
        var verificationResult = await opcSigner.Verify(unsignedHlkx, verificationOptions, ct: ct);

        verificationResult.Status.Should().Be(expectedStatus);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Non_Existent_Hardware_Lab_Kit_File.hlkx")]
    public async Task Given_an_invalid_hlkx_path_Sign_returns_Status_IoError(string filePath)
    {
        using var certificateProvider = GetTestCertificateProvider(HashAlgorithmName.SHA256, 2048);

        var opcSigner = new OpcSigner(
            certificateProvider,
            cryptoServiceProvider: null,
            digestHashAlgorithm: HashAlgorithmName.SHA256
        );
        var signResult = await opcSigner.Sign(filePath, ct: CancellationToken.None);
        signResult.Status.Should().Be(OpcSignStatus.IoError);
    }

    [Fact]
    public async Task Given_invalid_hlkx_file_Sign_returns_Status_InvalidData()
    {
        var invalidHlkx = GetTestFile("InvalidHlkxPackage");
        using var certificateProvider = GetTestCertificateProvider(HashAlgorithmName.SHA256, 2048);

        var opcSigner = new OpcSigner(
            certificateProvider,
            cryptoServiceProvider: null,
            digestHashAlgorithm: HashAlgorithmName.SHA256
        );
        var signResult = await opcSigner.Sign(invalidHlkx, ct: CancellationToken.None);
        signResult.Status.Should().Be(OpcSignStatus.InvalidData);
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
        using var certificateProvider = GetTestCertificateProvider(hashAlgorithm, rsaKeySizeInBits);

        var opcSigner = new OpcSigner(
            certificateProvider,
            cryptoServiceProvider: null,
            digestHashAlgorithm: hashAlgorithm
        );

        var signResult = await opcSigner.Sign(testFile, ct);
        signResult.ThrowIfFailed();
        var verifyResult = await opcSigner.Verify(testFile, ct: ct);
        verifyResult.ThrowIfFailed();
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

        using var testCertificate = GetTestCertificate(hashAlgorithm, rsaKeySizeInBits);
        using var publicCertificate = new X509Certificate2(
            testCertificate.Export(X509ContentType.Cert)
        );
        publicCertificate.GetRSAPrivateKey().Should().BeNull();
        using var certificateProvider = new X509CertificateProvider(publicCertificate);

        using var rsa = testCertificate.GetRSAPrivateKey();
        rsa.Should().NotBeNull();
        using var cryptoServiceProvider = new RsaCryptoServiceProvider(rsa!);

        var opcSigner = new OpcSigner(certificateProvider, cryptoServiceProvider, hashAlgorithm);
        var signResult = await opcSigner.Sign(testFile, ct);
        signResult.ThrowIfFailed();

        var verifyResult = await opcSigner.Verify(testFile, ct: ct);
        verifyResult.ThrowIfFailed();
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

        using var testCertificate = GetTestCertificate(hashAlgorithm, rsaKeySizeInBits);
        using var publicCertificate = new X509Certificate2(
            testCertificate.Export(X509ContentType.Cert)
        );
        publicCertificate.GetRSAPrivateKey().Should().BeNull();
        using var certificateProvider = new X509CertificateProvider(publicCertificate);

        using var rsa = testCertificate.GetRSAPrivateKey();
        rsa.Should().NotBeNull();
        using var cryptoServiceProvider = new RsaCryptoServiceProvider(rsa!);

        var opcSigner = new OpcSigner(certificateProvider, cryptoServiceProvider, hashAlgorithm);
        var signResult = await opcSigner.Sign(testFile, ct);
        signResult.ThrowIfFailed();

        var verifyResult = await opcSigner.Verify(testFile, ct: ct);
        verifyResult.ThrowIfFailed();
    }

    private static X509CertificateProvider GetTestCertificateProvider(
        HashAlgorithmName hashAlgorithm,
        int rsaKeySizeInBits
    ) => new(GetTestCertificate(hashAlgorithm, rsaKeySizeInBits));

    private static X509Certificate2 GetTestCertificate(
        HashAlgorithmName hashAlgorithm,
        int rsaKeySizeInBits
    ) =>
        X509CertificateProvider.CreateSelfSignedRsa(
            $"CN={typeof(OpcSignerTest).FullName}.{hashAlgorithm}_{rsaKeySizeInBits}",
            hashAlgorithm,
            rsaKeySizeInBits,
            365
        );

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
