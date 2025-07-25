using System.Text;
using System.Xml;

namespace AzureSign.Core.Opc.Models;

/// <summary>
/// Represents a part (file) within an OPC package.
/// </summary>
public class OpcPart
{
    public string Path { get; }
    public string ContentType { get; set; }
    public byte[] Content { get; set; }
    public bool IsModified { get; set; }

    public OpcPart(string path, string contentType, byte[] content)
    {
        Path = path ?? throw new ArgumentNullException(nameof(path));
        ContentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
        Content = content ?? throw new ArgumentNullException(nameof(content));
        IsModified = false;
    }

    /// <summary>
    /// Gets the content as a UTF-8 string.
    /// </summary>
    public string GetContentAsString()
    {
        return Encoding.UTF8.GetString(Content);
    }

    /// <summary>
    /// Gets the content as an XML document.
    /// </summary>
    public XmlDocument GetContentAsXml()
    {
        var doc = new XmlDocument();
        doc.LoadXml(GetContentAsString());
        return doc;
    }

    /// <summary>
    /// Updates the content from a string, marking the part as modified.
    /// </summary>
    public void UpdateContent(string content)
    {
        Content = Encoding.UTF8.GetBytes(content);
        IsModified = true;
    }

    /// <summary>
    /// Updates the content from bytes, marking the part as modified.
    /// </summary>
    public void UpdateContent(byte[] content)
    {
        Content = content ?? throw new ArgumentNullException(nameof(content));
        IsModified = true;
    }
}