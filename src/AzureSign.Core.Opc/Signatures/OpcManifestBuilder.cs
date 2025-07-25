using System.Security.Cryptography;
using System.Text;
using AzureSign.Core.Opc.Models;

namespace AzureSign.Core.Opc.Signatures;

/// <summary>
/// Builds OPC manifest XML for digital signatures.
/// </summary>
public class OpcManifestBuilder
{
    private readonly HashAlgorithmName _hashAlgorithm;

    public OpcManifestBuilder(HashAlgorithmName hashAlgorithm)
    {
        _hashAlgorithm = hashAlgorithm;
    }

    /// <summary>
    /// Creates the manifest XML containing references to parts and relationships.
    /// </summary>
    public string CreateManifest(IEnumerable<OpcPart> partsToSign, IEnumerable<OpcRelationship> relationshipsToSign)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<Manifest xmlns:opc=\"http://schemas.openxmlformats.org/package/2006/digital-signature\">");

        // Add part references
        foreach (var part in partsToSign)
        {
            var digest = ComputePartDigest(part);
            var contentType = part.ContentType;
            
            if (part.Path == "/_rels/.rels")
            {
                // Special handling for relationships file with canonicalization
                sb.AppendLine($"  <Reference URI=\"{part.Path}?ContentType={Uri.EscapeDataString(contentType)}\">");
                sb.AppendLine("    <Transforms>");
                sb.AppendLine("      <Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" />");
                sb.AppendLine("    </Transforms>");
                sb.AppendLine($"    <DigestMethod Algorithm=\"{GetDigestAlgorithm()}\" />");
                sb.AppendLine($"    <DigestValue>{digest}</DigestValue>");
                sb.AppendLine("  </Reference>");
            }
            else
            {
                // Regular part reference
                sb.AppendLine($"  <Reference URI=\"{part.Path}?ContentType={Uri.EscapeDataString(contentType)}\">");
                sb.AppendLine($"    <DigestMethod Algorithm=\"{GetDigestAlgorithm()}\" />");
                sb.AppendLine($"    <DigestValue>{digest}</DigestValue>");
                sb.AppendLine("  </Reference>");
            }
        }

        // Add relationship references with transforms
        if (relationshipsToSign.Any())
        {
            var relationshipDigest = ComputeRelationshipDigest(relationshipsToSign);
            sb.AppendLine("  <Reference URI=\"/_rels/.rels?ContentType=application/vnd.openxmlformats-package.relationships+xml\">");
            sb.AppendLine("    <Transforms>");
            sb.AppendLine("      <Transform Algorithm=\"http://schemas.openxmlformats.org/package/2006/RelationshipTransform\">");
            
            // Add relationship group references based on HLKX analysis
            foreach (var relType in GetUniqueRelationshipTypes(relationshipsToSign))
            {
                sb.AppendLine($"        <opc:RelationshipsGroupReference SourceType=\"{relType}\" />");
            }
            
            sb.AppendLine("      </Transform>");
            sb.AppendLine("      <Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" />");
            sb.AppendLine("    </Transforms>");
            sb.AppendLine($"    <DigestMethod Algorithm=\"{GetDigestAlgorithm()}\" />");
            sb.AppendLine($"    <DigestValue>{relationshipDigest}</DigestValue>");
            sb.AppendLine("  </Reference>");
        }

        sb.AppendLine("</Manifest>");
        return sb.ToString();
    }

    private string ComputePartDigest(OpcPart part)
    {
        byte[] contentToHash = part.Content;
        
        // Apply canonicalization for XML content if needed
        if (part.Path == "/_rels/.rels" || part.ContentType.Contains("xml"))
        {
            contentToHash = ApplyXmlCanonicalization(part.Content);
        }

        using var hasher = CreateHasher();
        var hash = hasher.ComputeHash(contentToHash);
        return Convert.ToBase64String(hash);
    }

    private string ComputeRelationshipDigest(IEnumerable<OpcRelationship> relationships)
    {
        // Create filtered relationships XML for signing
        var filteredXml = CreateFilteredRelationshipsXml(relationships);
        var canonicalizedXml = ApplyXmlCanonicalization(Encoding.UTF8.GetBytes(filteredXml));
        
        using var hasher = CreateHasher();
        var hash = hasher.ComputeHash(canonicalizedXml);
        return Convert.ToBase64String(hash);
    }

    private string CreateFilteredRelationshipsXml(IEnumerable<OpcRelationship> relationships)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
        sb.AppendLine("<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">");
        
        foreach (var rel in relationships.OrderBy(r => r.Id))
        {
            sb.AppendLine($"  <Relationship Type=\"{rel.RelationshipType}\" Target=\"{rel.Target}\" Id=\"{rel.Id}\" />");
        }
        
        sb.AppendLine("</Relationships>");
        return sb.ToString();
    }

    private byte[] ApplyXmlCanonicalization(byte[] xmlContent)
    {
        try
        {
            var xml = Encoding.UTF8.GetString(xmlContent);
            
            // Simple canonicalization - normalize whitespace and ensure consistent formatting
            // For production, you might want to use XmlDsigC14NTransform for full C14N compliance
            var normalized = xml
                .Replace("\r\n", "\n")
                .Replace("\r", "\n")
                .Trim();
            
            return Encoding.UTF8.GetBytes(normalized);
        }
        catch
        {
            // If XML parsing fails, return original content
            return xmlContent;
        }
    }

    private HashSet<string> GetUniqueRelationshipTypes(IEnumerable<OpcRelationship> relationships)
    {
        return relationships.Select(r => r.RelationshipType).ToHashSet();
    }

    private HashAlgorithm CreateHasher()
    {
        return _hashAlgorithm.Name switch
        {
            "SHA1" => SHA1.Create(),
            "SHA256" => SHA256.Create(),
            "SHA384" => SHA384.Create(),
            "SHA512" => SHA512.Create(),
            _ => SHA256.Create()
        };
    }

    private string GetDigestAlgorithm()
    {
        return _hashAlgorithm.Name switch
        {
            "SHA1" => "http://www.w3.org/2000/09/xmldsig#sha1",
            "SHA256" => "http://www.w3.org/2001/04/xmlenc#sha256",
            "SHA384" => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            "SHA512" => "http://www.w3.org/2001/04/xmlenc#sha512",
            _ => "http://www.w3.org/2001/04/xmlenc#sha256"
        };
    }
}