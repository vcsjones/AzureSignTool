using AzureSign.Core.Opc.Models;

namespace AzureSign.Core.Opc.Containers;

/// <summary>
/// Interface for HLKX OPC container operations.
/// </summary>
public interface IHlkxContainer : IDisposable
{
    /// <summary>
    /// Gets all parts in the container.
    /// </summary>
    IEnumerable<OpcPart> GetParts();

    /// <summary>
    /// Gets a specific part by path.
    /// </summary>
    OpcPart? GetPart(string path);

    /// <summary>
    /// Adds a new part to the container.
    /// </summary>
    void AddPart(string path, byte[] content, string contentType);

    /// <summary>
    /// Updates an existing part's content.
    /// </summary>
    void UpdatePart(string path, byte[] content);

    /// <summary>
    /// Gets all relationships in the container.
    /// </summary>
    IEnumerable<OpcRelationship> GetRelationships();

    /// <summary>
    /// Adds a relationship to the container.
    /// </summary>
    void AddRelationship(string target, string relationshipType, string? id = null);

    /// <summary>
    /// Adds signature-related parts to the container.
    /// </summary>
    void AddSignatureParts(Dictionary<string, byte[]> signatureParts);

    /// <summary>
    /// Removes all existing signatures from the container.
    /// </summary>
    void RemoveAllSignatures();

    /// <summary>
    /// Gets whether the container has any signatures.
    /// </summary>
    bool HasSignatures { get; }

    /// <summary>
    /// Updates the [Content_Types].xml file.
    /// </summary>
    void UpdateContentTypes();

    /// <summary>
    /// Saves all changes to the container.
    /// </summary>
    void Save();
}