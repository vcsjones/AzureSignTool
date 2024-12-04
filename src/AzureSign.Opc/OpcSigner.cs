using System.IO;
using System.IO.Compression;
using System.IO.Packaging;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AzureSign.Opc.Extensions;
using Microsoft.Extensions.Logging;

namespace AzureSign.Opc;

/// <summary>
/// A signer for OPC packages that supports using a custom RSA instance.
/// </summary>
/// <param name="certificateProvider">
/// The private or public certificate provider.
/// </param>
/// <param name="cryptoServiceProvider">
/// Optional RSA crypro provider. The crypto service provider is required
/// when the provided certificate does not contain the private key.
/// </param>
/// <param name="digestHashAlgorithm">
/// The hash algorithm to use when creating and verifying the OPC package signatures.
/// </param>
public class OpcSigner(
    IX509CertificateProvider certificateProvider,
    IRsaCryptoServiceProvider? cryptoServiceProvider,
    HashAlgorithmName digestHashAlgorithm,
    ILogger? logger = default
) : IOpcSigner
{
    /// <summary>
    /// Signs an OPC package with the provided certificate and RSA instance.
    /// </summary>
    /// <returns>
    /// Returns the OPC package signature.
    /// </returns>
    public async Task<OpcSignResult> Sign(string packagePath, CancellationToken ct = default)
    {
        if (!File.Exists(packagePath))
        {
            return OpcSignResult.Fail(OpcSignStatus.IoError, "File not found.");
        }
        try
        {
            var certificate = await certificateProvider.GetCertificateAsync(ct);
            using var package = Package.Open(packagePath);

            // Short circuit if the certificate contains an RSA private key
            if (certificate.GetRSAPrivateKey() is not null)
            {
                var packageSignature = SignPackage(package, certificate, digestHashAlgorithm);
                return OpcSignResult.Success(packageSignature.SignatureValue);
            }

            // Get the RSA instance from the provider and verify that the public key matches the certificate
            if (cryptoServiceProvider is null)
            {
                return OpcSignResult.Fail(
                    OpcSignStatus.CertificateError,
                    "Could not get an RSA instance. The provided certificate does not contain "
                        + "a private key and a custom RSA instance provider was not supplied."
                );
            }
            var rsa = await cryptoServiceProvider.GetRsaAsync(ct);
            if (!rsa.ExportRSAPublicKey().SequenceEqual(certificate.GetPublicKey()))
            {
                return OpcSignResult.Fail(
                    OpcSignStatus.CertificateError,
                    "The provided RSA public key does not match the provided certificate public key."
                );
            }

            // Self-sign the package with a temporary certificate using the PackageDigitalSignatureManager.
            // The PackageDigitalSignatureManager requires a certificate that contains a private key and
            // does not support using a custom RSA instance to sign the package part hashes.
            //
            // The purpose of self-signing is to avoid implementing the package signing logic, and instead replace
            // the applied certificate and signature with the ones from the provided certificate and RSA instance.
            using var selfSignedCert = X509CertificateProvider.CreateSelfSignedRsa(
                subjectName: "cn=TemporarySelfSignedHlkxCertificate",
                hashAlgorithm: digestHashAlgorithm,
                keySizeInBits: rsa.KeySize,
                expireInDays: 7,
                logger
            );
            // Hash the package parts and sign with the temporary certificate, the signature will be replaced below
            logger?.LogDebug("Hashing the package parts and signing with a temporary certificate.");
            var packageSignatureInfo = SignPackage(package, selfSignedCert, digestHashAlgorithm);

            // Get the package SignedInfo that holds the OPC package part/file list and hashes
            var c14nSignedInfo = packageSignatureInfo.GetC14nSignedInfo();
            package.Close();

            // Hash the package SignedInfo and sign the hash using the provided RSA instance
            logger?.LogDebug(
                "Hashing and signing using provided certificate: {CertificateSubject}.",
                certificate.Subject
            );
            var signatureValue = rsa.SignData(
                c14nSignedInfo,
                digestHashAlgorithm,
                RSASignaturePadding.Pkcs1
            );
            logger?.LogDebug(
                "Signed the package SignedInfo element that holds the package part list and hashes."
            );

            // Patch the package using the provided certificate and the new signature
            PatchPackageSignature(packagePath, certificate, signatureValue);

            // Return the OPC package signature
            return OpcSignResult.Success(packageSignatureInfo.SignatureValue);
        }
        catch (Exception ex)
        {
            return OpcSignResult.Fail(ex);
        }
    }

    /// <summary>
    /// Verifies the validity of OPC package signatures.
    /// </summary>
    public async Task<OpcVerifyResult> Verify(
        string packagePath,
        OpcVerifyOptions verificationOptions = OpcVerifyOptions.Default,
        CancellationToken ct = default
    )
    {
        if (!File.Exists(packagePath))
        {
            return OpcVerifyResult.Fail(OpcVerifyStatus.IoError, "File not found.");
        }
        try
        {
            var certificate = await certificateProvider.GetCertificateAsync(ct);
            var certificateSerialNumber = certificate.GetSerialNumberString();

            using var signedPackage = Package.Open(packagePath);
            var dsm = GetPackageDsm(signedPackage, digestHashAlgorithm);

            if (dsm.Signatures.Count == 0)
            {
                return OpcVerifyResult.Fail(OpcVerifyStatus.NotSigned);
            }
            if (verificationOptions.HasFlag(OpcVerifyOptions.VerifySignatureValidity))
            {
                var verifyResult = dsm.VerifySignatures(true);
                if (verifyResult is not VerifyResult.Success)
                {
                    return OpcVerifyResult.Fail(verifyResult);
                }
            }
            if (verificationOptions.HasFlag(OpcVerifyOptions.VerifyProviderCertificateMatch))
            {
                var unmatchedSignature = dsm
                    .Signatures.Where(s =>
                        s.Signer.GetSerialNumberString() != certificateSerialNumber
                    )
                    .FirstOrDefault();
                if (unmatchedSignature is not null)
                {
                    return OpcVerifyResult.Fail(
                        OpcVerifyStatus.UnmatchedPackagePart,
                        $"Unmatched certificate '{unmatchedSignature.Signer.Subject}' "
                            + $"found in signature part '{unmatchedSignature.SignaturePart.Uri}'. "
                            + $"Expected certificate '{certificate.Subject}'."
                    );
                }
            }
        }
        catch (Exception ex)
        {
            return OpcVerifyResult.Fail(ex);
        }
        return OpcVerifyResult.Success();
    }

    /// <summary>
    /// Sign an OPC package using a certificate that must contain a private key.
    /// </summary>
    private PackageDigitalSignature SignPackage(
        Package package,
        X509Certificate2 privateKeyCertificate,
        HashAlgorithmName hashAlgorithm
    )
    {
        if (!privateKeyCertificate.HasPrivateKey)
        {
            throw new ArgumentException("The provided certificate does not contain a private key.");
        }

        var dsm = GetPackageDsm(package, hashAlgorithm);
        dsm.RemoveAllSignatures();

        // Sign every part/file in the package
        var partsToSign = package.GetParts().Select(p => p.Uri).ToList();

        // Sign every relationship by type. This way the signature is
        // invalidated if *anything* is modified in the package post-signing
        var relationshipsToSign = package
            .GetRelationships()
            .Select(r => new PackageRelationshipSelector(
                r.SourceUri,
                PackageRelationshipSelectorType.Type,
                r.RelationshipType
            ))
            .ToList();

        var signature = dsm.Sign(partsToSign, privateKeyCertificate, relationshipsToSign);
        logger?.LogDebug(
            "{PartCount} package parts and {RelationshipCount} relationships signed with: '{CertificateSubject}'.",
            partsToSign.Count,
            relationshipsToSign.Count,
            signature.Signer.Subject
        );

        return signature;
    }

    private static PackageDigitalSignatureManager GetPackageDsm(
        Package signedPackage,
        HashAlgorithmName hashAlgorithm
    )
    {
        var hashAlgorithmNs = hashAlgorithm.Name switch
        {
            "SHA256" => "http://www.w3.org/2001/04/xmlenc#sha256",
            "SHA384" => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            "SHA512" => "http://www.w3.org/2001/04/xmlenc#sha512",
            _
                => throw new InvalidOperationException(
                    $"Unsupported hash algorithm '{hashAlgorithm.Name}'."
                ),
        };
        return new PackageDigitalSignatureManager(signedPackage)
        {
            CertificateOption = CertificateEmbeddingOption.InCertificatePart,
            HashAlgorithm = hashAlgorithmNs,
        };
    }

    /// <summary>
    /// Patch the OPC package signature with the provided certificate (public key only) and signature.
    /// </summary>
    private void PatchPackageSignature(
        string path,
        X509Certificate2 certificate,
        ReadOnlySpan<byte> newSignature
    )
    {
        using var packageZip = ZipFile.Open(path, ZipArchiveMode.Update);

        // Replace the embedded certificate with the provided certificate
        (var oldCertPath, var newCertPath) = packageZip.ReplaceOpcEmbeddedCertificate(certificate);
        logger?.LogDebug("Patched embedded certificate, with: '{NewCertPath}'.", newCertPath);

        // Replace the relationship target in the signature XML rels file entry
        packageZip.ReplaceOpcRelationshipTarget(oldCertPath, newCertPath);

        // Replace the hash in the packageSignature.SignatureValue
        packageZip.ReplaceOpcSignatureValue(newSignature);
        logger?.LogDebug("Patched package signature relationship target and signature value.");
    }
}
