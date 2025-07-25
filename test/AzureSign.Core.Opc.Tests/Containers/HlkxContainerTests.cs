using AzureSign.Core.Opc.Containers;
using AzureSign.Core.Opc.Tests.TestData;
using FluentAssertions;
using Xunit;

namespace AzureSign.Core.Opc.Tests.Containers;

public class HlkxContainerTests : IDisposable
{
    private readonly string _tempFile;

    public HlkxContainerTests()
    {
        _tempFile = Path.GetTempFileName();
        
        // Create synthetic HLKX file for testing
        SyntheticHlkxGenerator.CreateMinimalHlkx(_tempFile);
    }

    [Fact]
    public void Open_ValidHlkxFile_ShouldLoadParts()
    {
        // Arrange & Act
        using var container = HlkxContainer.Open(_tempFile);

        // Assert
        var parts = container.GetParts().ToList();
        parts.Should().NotBeEmpty();
        
        // Should have at least the basic OPC parts
        parts.Should().Contain(p => p.Path == "/[Content_Types].xml");
        parts.Should().Contain(p => p.Path == "/_rels/.rels");
        
        // Should have synthetic HCK data parts
        parts.Should().Contain(p => p.Path == "/hck/data/PackageInfo.xml");
        parts.Should().Contain(p => p.Path == "/hck/data/synthetic-data-1");
        parts.Should().Contain(p => p.Path == "/hck/data/synthetic-data-2");
    }

    [Fact]
    public void GetPart_ExistingPart_ShouldReturnPart()
    {
        // Arrange
        using var container = HlkxContainer.Open(_tempFile);

        // Act
        var part = container.GetPart("/_rels/.rels");

        // Assert
        part.Should().NotBeNull();
        part!.Path.Should().Be("/_rels/.rels");
        part.ContentType.Should().Be("application/vnd.openxmlformats-package.relationships+xml");
    }

    [Fact]
    public void AddPart_NewPart_ShouldAddToContainer()
    {
        // Arrange
        using var container = HlkxContainer.Open(_tempFile);
        var testContent = "test content"u8.ToArray();

        // Act
        container.AddPart("/test/part.txt", testContent, "text/plain");

        // Assert
        var part = container.GetPart("/test/part.txt");
        part.Should().NotBeNull();
        part!.Content.Should().BeEquivalentTo(testContent);
        part.ContentType.Should().Be("text/plain");
    }

    [Fact]
    public void HasSignatures_UnsignedFile_ShouldReturnFalse()
    {
        // Arrange
        using var container = HlkxContainer.Open(_tempFile);

        // Act & Assert
        container.HasSignatures.Should().BeFalse();
    }

    [Fact]
    public void AddSignatureParts_ValidParts_ShouldAddToContainer()
    {
        // Arrange
        using var container = HlkxContainer.Open(_tempFile);
        var signatureParts = new Dictionary<string, byte[]>
        {
            ["/package/services/digital-signature/origin.psdsor"] = Array.Empty<byte>(),
            ["/package/services/digital-signature/xml-signature/test.psdsxs"] = "<signature>test</signature>"u8.ToArray()
        };

        // Act
        container.AddSignatureParts(signatureParts);

        // Assert
        container.HasSignatures.Should().BeTrue();
        container.GetPart("/package/services/digital-signature/origin.psdsor").Should().NotBeNull();
        container.GetPart("/package/services/digital-signature/xml-signature/test.psdsxs").Should().NotBeNull();
    }

    [Fact]
    public void HasSignatures_PreSignedFile_ShouldReturnTrue()
    {
        // Arrange
        var preSignedFile = Path.GetTempFileName();
        SyntheticHlkxGenerator.CreatePreSignedHlkx(preSignedFile);

        try
        {
            using var container = HlkxContainer.Open(preSignedFile);

            // Act & Assert
            container.HasSignatures.Should().BeTrue();
            
            // Should have signature parts
            container.GetPart("/package/services/digital-signature/origin.psdsor").Should().NotBeNull();
            var xmlSigParts = container.GetParts().Where(p => p.Path.Contains("xml-signature") && p.Path.EndsWith(".psdsxs"));
            xmlSigParts.Should().NotBeEmpty();
        }
        finally
        {
            if (File.Exists(preSignedFile))
                File.Delete(preSignedFile);
        }
    }

    public void Dispose()
    {
        if (File.Exists(_tempFile))
        {
            File.Delete(_tempFile);
        }
    }
}