namespace AzureSign.Core.Opc.Models;

/// <summary>
/// Represents a relationship within an OPC package.
/// </summary>
public class OpcRelationship
{
    public string Id { get; }
    public string RelationshipType { get; }
    public string Target { get; }
    public string SourceUri { get; }

    public OpcRelationship(string id, string relationshipType, string target, string sourceUri = "/")
    {
        Id = id ?? throw new ArgumentNullException(nameof(id));
        RelationshipType = relationshipType ?? throw new ArgumentNullException(nameof(relationshipType));
        Target = target ?? throw new ArgumentNullException(nameof(target));
        SourceUri = sourceUri ?? throw new ArgumentNullException(nameof(sourceUri));
    }

    /// <summary>
    /// Creates a relationship XML element.
    /// </summary>
    public string ToXmlElement()
    {
        return $"<Relationship Type=\"{RelationshipType}\" Target=\"{Target}\" Id=\"{Id}\" />";
    }
}