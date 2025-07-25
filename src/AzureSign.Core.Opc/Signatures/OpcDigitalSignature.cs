using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AzureSign.Core.Opc.Signatures;

/// <summary>
/// Represents an OPC digital signature with all its components.
/// </summary>
public class OpcDigitalSignature
{
    public string SignatureId { get; }
    public byte[] SignatureValue { get; }
    public X509Certificate2 Certificate { get; }
    public DateTime SignatureTime { get; }
    public HashAlgorithmName HashAlgorithm { get; }
    public string ManifestXml { get; }

    public OpcDigitalSignature(
        string signatureId,
        byte[] signatureValue,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        string manifestXml)
    {
        SignatureId = signatureId ?? throw new ArgumentNullException(nameof(signatureId));
        SignatureValue = signatureValue ?? throw new ArgumentNullException(nameof(signatureValue));
        Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        HashAlgorithm = hashAlgorithm;
        ManifestXml = manifestXml ?? throw new ArgumentNullException(nameof(manifestXml));
        SignatureTime = DateTime.UtcNow;
    }

    /// <summary>
    /// Generates all OPC signature parts required for the package.
    /// </summary>
    public Dictionary<string, byte[]> GenerateSignatureParts()
    {
        var parts = new Dictionary<string, byte[]>();

        // Certificate hash for filename
        var certHash = GetCertificateHash();

        // 1. Origin marker (empty file)
        parts["/package/services/digital-signature/origin.psdsor"] = Array.Empty<byte>();

        // 2. XML signature
        var xmlSignature = CreateXmlSignature();
        parts[$"/package/services/digital-signature/xml-signature/{SignatureId}.psdsxs"] = xmlSignature;

        // 3. Certificate
        parts[$"/package/services/digital-signature/certificate/{certHash}.cer"] = Certificate.RawData;

        // 4. Origin relationships
        var originRels = CreateOriginRelationships();
        parts["/package/services/digital-signature/_rels/origin.psdsor.rels"] = originRels;

        // 5. Signature relationships
        var sigRels = CreateSignatureRelationships(certHash);
        parts[$"/package/services/digital-signature/xml-signature/_rels/{SignatureId}.psdsxs.rels"] = sigRels;

        return parts;
    }

    /// <summary>
    /// Creates the XML signature document based on the HLKX reference structure.
    /// </summary>
    private byte[] CreateXmlSignature()
    {
        var xml = $@"<?xml version=""1.0"" encoding=""utf-8"" standalone=""yes""?>
<Signature Id=""SignatureIdValue"" xmlns=""http://www.w3.org/2000/09/xmldsig#"">
  <SignedInfo>
    <CanonicalizationMethod Algorithm=""http://www.w3.org/TR/2001/REC-xml-c14n-20010315"" />
    <SignatureMethod Algorithm=""{GetSignatureMethodAlgorithm()}"" />
    <Reference URI=""#idPackageObject"" Type=""http://www.w3.org/2000/09/xmldsig#Object"">
      <DigestMethod Algorithm=""{GetDigestAlgorithm()}"" />
      <DigestValue>{ComputeManifestDigest()}</DigestValue>
    </Reference>
  </SignedInfo>
  <SignatureValue>{Convert.ToBase64String(SignatureValue)}</SignatureValue>
  <Object Id=""idPackageObject"">
    {ManifestXml}
    <SignatureProperties>
      <SignatureProperty Id=""idSignatureTime"" Target=""#SignatureIdValue"">
        <SignatureTime xmlns=""http://schemas.openxmlformats.org/package/2006/digital-signature"">
          <Format>YYYY-MM-DDThh:mm:ss.sTZD</Format>
          <Value>{SignatureTime:yyyy-MM-ddTHH:mm:ss.fK}</Value>
        </SignatureTime>
      </SignatureProperty>
    </SignatureProperties>
  </Object>
</Signature>";

        return System.Text.Encoding.UTF8.GetBytes(xml);
    }

    private byte[] CreateOriginRelationships()
    {
        var xml = $@"<?xml version=""1.0"" encoding=""utf-8""?>
<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships"">
  <Relationship Type=""http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature"" Target=""/package/services/digital-signature/xml-signature/{SignatureId}.psdsxs"" Id=""R{Guid.NewGuid():N""[..12]}"" />
</Relationships>";

        return System.Text.Encoding.UTF8.GetBytes(xml);
    }

    private byte[] CreateSignatureRelationships(string certHash)
    {
        var xml = $@"<?xml version=""1.0"" encoding=""utf-8""?>
<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships"">
  <Relationship Type=""http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/certificate"" Target=""/package/services/digital-signature/certificate/{certHash}.cer"" Id=""R{Guid.NewGuid():N""[..12]}"" />
</Relationships>";

        return System.Text.Encoding.UTF8.GetBytes(xml);
    }

    private string GetCertificateHash()
    {
        using var sha1 = SHA1.Create();
        var hash = sha1.ComputeHash(Certificate.RawData);
        return Convert.ToHexString(hash);
    }

    private string GetSignatureMethodAlgorithm()
    {
        return HashAlgorithm.Name switch
        {
            "SHA1" => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            "SHA256" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "SHA384" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            "SHA512" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            _ => "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        };
    }

    private string GetDigestAlgorithm()
    {
        return HashAlgorithm.Name switch
        {
            "SHA1" => "http://www.w3.org/2000/09/xmldsig#sha1",
            "SHA256" => "http://www.w3.org/2001/04/xmlenc#sha256",
            "SHA384" => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            "SHA512" => "http://www.w3.org/2001/04/xmlenc#sha512",
            _ => "http://www.w3.org/2000/09/xmldsig#sha1"
        };
    }

    private string ComputeManifestDigest()
    {
        var manifestBytes = System.Text.Encoding.UTF8.GetBytes(ManifestXml);
        
        using System.Security.Cryptography.HashAlgorithm hasher = HashAlgorithm.Name switch
        {
            "SHA1" => SHA1.Create(),
            "SHA256" => SHA256.Create(),
            "SHA384" => SHA384.Create(),
            "SHA512" => SHA512.Create(),
            _ => SHA1.Create()
        };

        var hash = hasher.ComputeHash(manifestBytes);
        return Convert.ToBase64String(hash);
    }
}