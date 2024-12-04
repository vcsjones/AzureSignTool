using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AzureSign.Opc.Tests.TestData;

namespace AzureSign.Opc.Tests;

public class X509CertificateProviderTest
{
    [Fact]
    public async Task GetCertificateAsync_returns_the_certificate_given_during_construction()
    {
        var ct = TestContext.Current.CancellationToken;

        var hashAlgorithm = HashAlgorithmName.SHA384;
        var rsaKeySizeInBits = 3072;

        using var expectedCertificate = X509CertificateProvider.CreateSelfSignedRsa(
            $"CN={typeof(X509CertificateProviderTest).FullName}.{hashAlgorithm}_{rsaKeySizeInBits}",
            hashAlgorithm,
            keySizeInBits: rsaKeySizeInBits,
            expireInDays: 7
        );

        var provider = new X509CertificateProvider(expectedCertificate);
        var certificate = await provider.GetCertificateAsync(ct);

        certificate.Should().BeSameAs(expectedCertificate);
    }

    [Theory]
    [ClassData(typeof(CertificateTestData))]
    public void Given_hash_algorithm_and_key_size_CreateSelfSignedRsa_returns_X509_certificate_with_private_key(
        HashAlgorithmName hashAlgorithm,
        int rsaKeySizeInBits
    )
    {
        using var selfSignedCert = X509CertificateProvider.CreateSelfSignedRsa(
            $"CN={typeof(X509CertificateProviderTest).FullName}.{hashAlgorithm}_{rsaKeySizeInBits}",
            hashAlgorithm,
            keySizeInBits: rsaKeySizeInBits,
            expireInDays: 7
        );

        selfSignedCert.GetSerialNumberString().Should().NotBeNullOrEmpty();
        selfSignedCert.GetRSAPublicKey().Should().NotBeNull();
        selfSignedCert.GetRSAPrivateKey().Should().NotBeNull();
    }
}
