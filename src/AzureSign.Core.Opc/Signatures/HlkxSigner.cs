using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AzureSign.Core.Opc.Containers;
using AzureSign.Core.Opc.Models;
using Microsoft.Extensions.Logging;

namespace AzureSign.Core.Opc.Signatures;

/// <summary>
/// HLKX package signer implementation that works with Azure Key Vault HSM certificates.
/// </summary>
public class HlkxSigner : IHlkxSigner
{
    private const int S_OK = 0;
    private const int E_FAIL = unchecked((int)0x80004005);
    private const int E_INVALIDARG = unchecked((int)0x80070057);

    public async Task<int> SignFileAsync(
        string filePath,
        AsymmetricAlgorithm signingAlgorithm,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        ILogger? logger = null)
    {
        try
        {
            logger?.LogInformation("Starting HLKX signing process for: {FilePath}", filePath);

            if (!File.Exists(filePath))
            {
                logger?.LogError("HLKX file not found: {FilePath}", filePath);
                return E_INVALIDARG;
            }

            using var container = HlkxContainer.Open(filePath);
            
            // Remove any existing signatures
            container.RemoveAllSignatures();
            
            // Get parts and relationships that need to be signed
            var partsToSign = GetPartsRequiringSignature(container).ToList();
            var relationshipsToSign = GetRelationshipsRequiringSignature(container).ToList();

            logger?.LogDebug("Found {PartCount} parts and {RelationshipCount} relationships to sign",
                partsToSign.Count, relationshipsToSign.Count);

            // Create manifest
            var manifestBuilder = new OpcManifestBuilder(hashAlgorithm);
            var manifestXml = manifestBuilder.CreateManifest(partsToSign, relationshipsToSign);

            // Create temporary certificate for the signing structure
            // This follows the fork's proven approach for HSM integration
            using var tempCert = CreateTemporaryCertificate(signingAlgorithm, hashAlgorithm, logger);
            
            // Prepare SignedInfo for signing
            var signedInfoData = PrepareSignedInfo(manifestXml, hashAlgorithm);
            
            // Sign with Azure Key Vault (remote operation)
            logger?.LogDebug("Performing remote signing operation with Azure Key Vault");
            var signatureValue = await PerformRemoteSigningAsync(signingAlgorithm, signedInfoData, hashAlgorithm);

            // Create final digital signature
            var signatureId = Guid.NewGuid().ToString("N");
            var signature = new OpcDigitalSignature(
                signatureId,
                signatureValue,
                certificate,
                hashAlgorithm,
                manifestXml);

            // Add signature parts to container
            var signatureParts = signature.GenerateSignatureParts();
            container.AddSignatureParts(signatureParts);

            // Add signature relationship to root
            container.AddRelationship(
                "/package/services/digital-signature/origin.psdsor",
                "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin");

            // Save the signed container
            container.Save();

            logger?.LogInformation("HLKX file signed successfully");
            return S_OK;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to sign HLKX file: {FilePath}", filePath);
            return E_FAIL;
        }
    }

    public async Task<bool> VerifyFileAsync(string filePath, ILogger? logger = null)
    {
        try
        {
            logger?.LogInformation("Verifying HLKX signature for: {FilePath}", filePath);

            if (!File.Exists(filePath))
            {
                logger?.LogError("HLKX file not found: {FilePath}", filePath);
                return false;
            }

            using var container = HlkxContainer.Open(filePath);
            
            if (!container.HasSignatures)
            {
                logger?.LogWarning("HLKX file has no signatures: {FilePath}", filePath);
                return false;
            }

            // Basic verification - check if signature parts exist and are well-formed
            // For full cryptographic verification, you would need to:
            // 1. Parse the XML signature
            // 2. Recalculate part digests
            // 3. Verify the signature against the certificate
            // 4. Check certificate chain validity

            var signatureParts = container.GetParts()
                .Where(p => p.Path.StartsWith("/package/services/digital-signature/"))
                .ToList();

            logger?.LogDebug("Found {SignaturePartCount} signature parts", signatureParts.Count);

            // Minimal validation - ensure we have the required signature components
            var hasOrigin = signatureParts.Any(p => p.Path.EndsWith("origin.psdsor"));
            var hasXmlSignature = signatureParts.Any(p => p.Path.Contains("xml-signature") && p.Path.EndsWith(".psdsxs"));
            var hasCertificate = signatureParts.Any(p => p.Path.Contains("certificate") && p.Path.EndsWith(".cer"));

            var isValid = hasOrigin && hasXmlSignature && hasCertificate;
            
            logger?.LogInformation("HLKX signature verification result: {IsValid}", isValid);
            return isValid;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to verify HLKX file: {FilePath}", filePath);
            return false;
        }
    }

    /// <summary>
    /// Gets the parts that require signing based on HLKX specification.
    /// </summary>
    private IEnumerable<OpcPart> GetPartsRequiringSignature(IHlkxContainer container)
    {
        foreach (var part in container.GetParts())
        {
            // Sign all data parts (critical for HLKX validation)
            if (part.Path.StartsWith("/hck/data/") || 
                part.Path == "/_rels/.rels")
            {
                yield return part;
            }
        }
    }

    /// <summary>
    /// Gets the relationships that require signing based on HLKX specification.
    /// </summary>
    private IEnumerable<OpcRelationship> GetRelationshipsRequiringSignature(IHlkxContainer container)
    {
        // Sign specific relationship types found in the analysis
        var targetTypes = new HashSet<string>
        {
            "http://microsoft.com/schemas/windows/kits/hardware/2010/streamdata",
            "http://microsoft.com/schemas/windows/kits/hardware/2010/coredata",
            "http://microsoft.com/schemas/windows/kits/hardware/2010/packageinfo",
            "http://microsoft.com/shcemas/windows/kits/hardware/2010/packageinfo" // Note: typo in original spec
        };

        return container.GetRelationships()
            .Where(r => targetTypes.Contains(r.RelationshipType));
    }

    /// <summary>
    /// Creates a temporary self-signed certificate for the signing process.
    /// This follows the fork's proven approach for HSM integration.
    /// </summary>
    private X509Certificate2 CreateTemporaryCertificate(
        AsymmetricAlgorithm signingAlgorithm, 
        HashAlgorithmName hashAlgorithm,
        ILogger? logger)
    {
        logger?.LogDebug("Creating temporary certificate for signing structure");

        var rsa = signingAlgorithm as RSA ?? throw new ArgumentException("Only RSA algorithms are supported");
        
        var request = new CertificateRequest(
            "CN=TemporarySelfSignedHlkxCertificate",
            rsa,
            hashAlgorithm,
            RSASignaturePadding.Pkcs1);

        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(7));

        logger?.LogDebug("Created temporary certificate with thumbprint: {Thumbprint}", certificate.Thumbprint);
        return certificate;
    }

    /// <summary>
    /// Prepares the SignedInfo data for signing.
    /// </summary>
    private byte[] PrepareSignedInfo(string manifestXml, HashAlgorithmName hashAlgorithm)
    {
        // Create SignedInfo element
        var digestAlgorithm = GetDigestAlgorithmUrl(hashAlgorithm);
        var signatureMethod = GetSignatureMethodUrl(hashAlgorithm);
        
        // Compute manifest digest
        var manifestBytes = System.Text.Encoding.UTF8.GetBytes(manifestXml);
        using var hasher = CreateHasher(hashAlgorithm);
        var manifestDigest = Convert.ToBase64String(hasher.ComputeHash(manifestBytes));

        var signedInfo = $@"<SignedInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
  <CanonicalizationMethod Algorithm=""http://www.w3.org/TR/2001/REC-xml-c14n-20010315"" />
  <SignatureMethod Algorithm=""{signatureMethod}"" />
  <Reference URI=""#idPackageObject"" Type=""http://www.w3.org/2000/09/xmldsig#Object"">
    <DigestMethod Algorithm=""{digestAlgorithm}"" />
    <DigestValue>{manifestDigest}</DigestValue>
  </Reference>
</SignedInfo>";

        return System.Text.Encoding.UTF8.GetBytes(signedInfo);
    }

    /// <summary>
    /// Performs the actual signing operation using the Azure Key Vault RSA instance.
    /// </summary>
    private async Task<byte[]> PerformRemoteSigningAsync(
        AsymmetricAlgorithm signingAlgorithm,
        byte[] dataToSign,
        HashAlgorithmName hashAlgorithm)
    {
        if (signingAlgorithm is RSA rsa)
        {
            // For RSA, we can use SignData directly
            return rsa.SignData(dataToSign, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }
        else if (signingAlgorithm is ECDsa ecdsa)
        {
            // For ECDSA, we need to hash first then sign
            using var hasher = CreateHasher(hashAlgorithm);
            var hash = hasher.ComputeHash(dataToSign);
            return ecdsa.SignHash(hash);
        }
        else
        {
            throw new NotSupportedException($"Signing algorithm {signingAlgorithm.GetType().Name} is not supported");
        }
    }

    private HashAlgorithm CreateHasher(HashAlgorithmName hashAlgorithm)
    {
        return hashAlgorithm.Name switch
        {
            "SHA1" => SHA1.Create(),
            "SHA256" => SHA256.Create(),
            "SHA384" => SHA384.Create(),
            "SHA512" => SHA512.Create(),
            _ => SHA256.Create()
        };
    }

    private string GetDigestAlgorithmUrl(HashAlgorithmName hashAlgorithm)
    {
        return hashAlgorithm.Name switch
        {
            "SHA1" => "http://www.w3.org/2000/09/xmldsig#sha1",
            "SHA256" => "http://www.w3.org/2001/04/xmlenc#sha256",
            "SHA384" => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            "SHA512" => "http://www.w3.org/2001/04/xmlenc#sha512",
            _ => "http://www.w3.org/2001/04/xmlenc#sha256"
        };
    }

    private string GetSignatureMethodUrl(HashAlgorithmName hashAlgorithm)
    {
        return hashAlgorithm.Name switch
        {
            "SHA1" => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            "SHA256" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "SHA384" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            "SHA512" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            _ => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        };
    }
}