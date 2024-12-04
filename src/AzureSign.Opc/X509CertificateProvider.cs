using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;

namespace AzureSign.Opc;

public sealed class X509CertificateProvider : IX509CertificateProvider
{
    private readonly X509Certificate2? _injectedCertificate;
    private readonly Func<CancellationToken, Task<X509Certificate2>>? _certificateRequester;
    private X509Certificate2? _keyVaultCertificate;

    public X509CertificateProvider(X509Certificate2 certificate)
    {
        _injectedCertificate = certificate;
    }

    public X509CertificateProvider(TokenCredential credential, Uri vaultUri, string certificateName)
    {
        _certificateRequester = (ct) =>
            GetKeyVaultCertificate(credential, vaultUri, certificateName, ct);
    }

    /// <summary>
    /// Gets the X509 certificate from the provider (may contain public key only).
    /// </summary>
    public async Task<X509Certificate2> GetCertificateAsync(CancellationToken ct)
    {
        if (_injectedCertificate is not null)
        {
            return _injectedCertificate;
        }
        if (_certificateRequester is null)
        {
            throw new InvalidOperationException("Certificate not provided.");
        }
        return (_keyVaultCertificate ??= await _certificateRequester(ct));
    }

    /// <summary>
    /// Creates a self-signed X509 certificate (with private key).
    /// </summary>
    public static X509Certificate2 CreateSelfSignedRsa(
        string subjectName,
        HashAlgorithmName hashAlgorithm,
        int keySizeInBits,
        int expireInDays,
        ILogger? logger = default
    )
    {
        using var rsa = RSA.Create(keySizeInBits);
        var utcNow = DateTimeOffset.UtcNow;
        var request = new CertificateRequest(
            subjectName,
            rsa,
            hashAlgorithm,
            RSASignaturePadding.Pkcs1
        );
        var selfSigned = request.CreateSelfSigned(utcNow.AddDays(-1), utcNow.AddDays(expireInDays));

        logger?.LogDebug(
            "Self signed certificate created: '{CertificateSubject}' "
                + "(KeySize={KeySizeInBits} bits, Expiry={ExpireInDays} days).",
            selfSigned.Subject,
            keySizeInBits,
            expireInDays
        );
        return selfSigned;
    }

    private static async Task<X509Certificate2> GetKeyVaultCertificate(
        TokenCredential credential,
        Uri vaultUri,
        string certificateName,
        CancellationToken ct
    )
    {
        var certificateClient = new CertificateClient(vaultUri, credential);
        var response = await certificateClient.GetCertificateAsync(certificateName, ct);
        return new X509Certificate2(response.Value.Cer);
    }

    public void Dispose()
    {
        _keyVaultCertificate?.Dispose();
    }
}
