using System.IO.Compression;
using System.Text;
using System.Xml;
using AzureSign.Core.Opc.Models;

namespace AzureSign.Core.Opc.Containers;

/// <summary>
/// ZIP-based implementation of HLKX OPC container.
/// </summary>
public class HlkxContainer : IHlkxContainer
{
    private readonly string _filePath;
    private readonly ZipArchive _archive;
    private readonly Dictionary<string, OpcPart> _parts;
    private readonly List<OpcRelationship> _relationships;
    private bool _modified;
    private bool _disposed;

    private HlkxContainer(string filePath, ZipArchive archive)
    {
        _filePath = filePath;
        _archive = archive;
        _parts = new Dictionary<string, OpcPart>();
        _relationships = new List<OpcRelationship>();
        _modified = false;

        LoadContainer();
    }

    /// <summary>
    /// Opens an existing HLKX file for reading and modification.
    /// </summary>
    public static HlkxContainer Open(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"HLKX file not found: {filePath}");

        var archive = ZipFile.Open(filePath, ZipArchiveMode.Update);
        return new HlkxContainer(filePath, archive);
    }

    public IEnumerable<OpcPart> GetParts() => _parts.Values;

    public OpcPart? GetPart(string path) => _parts.TryGetValue(path, out var part) ? part : null;

    public void AddPart(string path, byte[] content, string contentType)
    {
        var part = new OpcPart(path, contentType, content) { IsModified = true };
        _parts[path] = part;
        _modified = true;
    }

    public void UpdatePart(string path, byte[] content)
    {
        if (_parts.TryGetValue(path, out var part))
        {
            part.UpdateContent(content);
            _modified = true;
        }
        else
        {
            throw new InvalidOperationException($"Part not found: {path}");
        }
    }

    public IEnumerable<OpcRelationship> GetRelationships() => _relationships;

    public void AddRelationship(string target, string relationshipType, string? id = null)
    {
        id ??= GenerateRelationshipId();
        var relationship = new OpcRelationship(id, relationshipType, target);
        _relationships.Add(relationship);
        _modified = true;
    }

    public void AddSignatureParts(Dictionary<string, byte[]> signatureParts)
    {
        foreach (var kvp in signatureParts)
        {
            var contentType = GetSignaturePartContentType(kvp.Key);
            AddPart(kvp.Key, kvp.Value, contentType);
        }
    }

    public void RemoveAllSignatures()
    {
        // Remove signature-related parts
        var signatureParts = _parts.Keys
            .Where(path => path.StartsWith("/package/services/digital-signature/"))
            .ToList();

        foreach (var partPath in signatureParts)
        {
            _parts.Remove(partPath);
        }

        // Remove signature relationships
        var signatureRelationships = _relationships
            .Where(r => r.RelationshipType.Contains("digital-signature"))
            .ToList();

        foreach (var rel in signatureRelationships)
        {
            _relationships.Remove(rel);
        }

        if (signatureParts.Any() || signatureRelationships.Any())
        {
            _modified = true;
        }
    }

    public bool HasSignatures => _parts.Keys.Any(path => path.StartsWith("/package/services/digital-signature/"));

    public void UpdateContentTypes()
    {
        var contentTypesXml = BuildContentTypesXml();
        AddPart("/[Content_Types].xml", Encoding.UTF8.GetBytes(contentTypesXml), 
                "application/vnd.openxmlformats-package.content-types+xml");
    }

    public void Save()
    {
        if (!_modified) return;

        // Update relationships
        UpdateRelationshipsFile();

        // Update content types
        UpdateContentTypes();

        // Write all modified parts to ZIP
        foreach (var part in _parts.Values.Where(p => p.IsModified))
        {
            WritePartToArchive(part);
        }

        _modified = false;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            Save();
            _archive?.Dispose();
            _disposed = true;
        }
    }

    private void LoadContainer()
    {
        // Load all parts from ZIP archive
        foreach (var entry in _archive.Entries)
        {
            if (entry.FullName.EndsWith('/')) continue; // Skip directories

            var path = "/" + entry.FullName.Replace('\\', '/');
            var contentType = GetContentTypeFromPath(path);
            
            using var stream = entry.Open();
            using var memoryStream = new MemoryStream();
            stream.CopyTo(memoryStream);
            var content = memoryStream.ToArray();

            _parts[path] = new OpcPart(path, contentType, content);
        }

        // Load relationships from _rels/.rels
        LoadRelationships();
    }

    private void LoadRelationships()
    {
        var relsPart = GetPart("/_rels/.rels");
        if (relsPart == null) return;

        try
        {
            var doc = relsPart.GetContentAsXml();
            var nsManager = new XmlNamespaceManager(doc.NameTable);
            nsManager.AddNamespace("r", "http://schemas.openxmlformats.org/package/2006/relationships");

            var relationshipNodes = doc.SelectNodes("//r:Relationship", nsManager);
            if (relationshipNodes == null) return;

            foreach (XmlNode node in relationshipNodes)
            {
                if (node.Attributes == null) continue;

                var id = node.Attributes["Id"]?.Value;
                var type = node.Attributes["Type"]?.Value;
                var target = node.Attributes["Target"]?.Value;

                if (id != null && type != null && target != null)
                {
                    _relationships.Add(new OpcRelationship(id, type, target));
                }
            }
        }
        catch (XmlException)
        {
            // Handle invalid XML gracefully
        }
    }

    private void UpdateRelationshipsFile()
    {
        var xml = BuildRelationshipsXml();
        var content = Encoding.UTF8.GetBytes(xml);
        
        if (_parts.ContainsKey("/_rels/.rels"))
        {
            UpdatePart("/_rels/.rels", content);
        }
        else
        {
            AddPart("/_rels/.rels", content, "application/vnd.openxmlformats-package.relationships+xml");
        }
    }

    private string BuildRelationshipsXml()
    {
        var sb = new StringBuilder();
        sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
        sb.AppendLine("<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">");
        
        foreach (var rel in _relationships)
        {
            sb.AppendLine($"  <Relationship Type=\"{rel.RelationshipType}\" Target=\"{rel.Target}\" Id=\"{rel.Id}\" />");
        }
        
        sb.AppendLine("</Relationships>");
        return sb.ToString();
    }

    private string BuildContentTypesXml()
    {
        var sb = new StringBuilder();
        sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
        sb.AppendLine("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">");
        
        // Default extensions
        sb.AppendLine("  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\" />");
        sb.AppendLine("  <Default Extension=\"xml\" ContentType=\"application/octet\" />");
        sb.AppendLine("  <Default Extension=\"txt\" ContentType=\"application/octet\" />");
        
        // Signature-specific content types
        sb.AppendLine("  <Default Extension=\"psdsor\" ContentType=\"application/vnd.openxmlformats-package.digital-signature-origin\" />");
        sb.AppendLine("  <Default Extension=\"psdsxs\" ContentType=\"application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml\" />");
        sb.AppendLine("  <Default Extension=\"cer\" ContentType=\"application/vnd.openxmlformats-package.digital-signature-certificate\" />");
        
        // Override for specific parts
        foreach (var part in _parts.Values)
        {
            if (part.Path.StartsWith("/hck/data/") && !part.Path.EndsWith(".xml"))
            {
                sb.AppendLine($"  <Override PartName=\"{part.Path}\" ContentType=\"application/octet\" />");
            }
        }
        
        sb.AppendLine("</Types>");
        return sb.ToString();
    }

    private void WritePartToArchive(OpcPart part)
    {
        var entryName = part.Path.TrimStart('/');
        
        // Remove existing entry if it exists
        var existingEntry = _archive.GetEntry(entryName);
        existingEntry?.Delete();

        // Create new entry
        var entry = _archive.CreateEntry(entryName);
        using var stream = entry.Open();
        stream.Write(part.Content);
    }

    private string GetContentTypeFromPath(string path)
    {
        return path switch
        {
            "/_rels/.rels" => "application/vnd.openxmlformats-package.relationships+xml",
            "/[Content_Types].xml" => "application/vnd.openxmlformats-package.content-types+xml",
            var p when p.EndsWith(".psdsor") => "application/vnd.openxmlformats-package.digital-signature-origin",
            var p when p.EndsWith(".psdsxs") => "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml",
            var p when p.EndsWith(".cer") => "application/vnd.openxmlformats-package.digital-signature-certificate",
            _ => "application/octet"
        };
    }

    private string GetSignaturePartContentType(string path)
    {
        return path switch
        {
            var p when p.EndsWith("origin.psdsor") => "application/vnd.openxmlformats-package.digital-signature-origin",
            var p when p.EndsWith(".psdsxs") => "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml",
            var p when p.EndsWith(".cer") => "application/vnd.openxmlformats-package.digital-signature-certificate",
            var p when p.Contains("/_rels/") => "application/vnd.openxmlformats-package.relationships+xml",
            _ => "application/octet"
        };
    }

    private string GenerateRelationshipId()
    {
        return "R" + Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();
    }
}