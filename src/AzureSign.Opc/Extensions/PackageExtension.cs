using System.IO;
using System.IO.Packaging;
using System.Xml;
using System.Xml.Serialization;

namespace AzureSign.Opc.Extensions;

internal static class PackageExtension
{
    public static void AddXmlPart<T>(
        this Package package,
        string relativeUri,
        T value,
        string xmlNamespace
    )
    {
        var serializer = new XmlSerializer(typeof(T));
        var packagePart = package.CreatePart(new Uri(relativeUri, UriKind.Relative), "text/xml");
        using var stream = packagePart.GetStream();
        serializer.Serialize(stream, value);
        package.CreateRelationship(packagePart.Uri, TargetMode.Internal, xmlNamespace);
    }

    /// <summary>
    /// Get the C14N canonicalized representation of the SignedInfo XML.
    /// Based on System.Security.Cryptography.Xml.SignedXml.GetC14NDigest.
    /// </summary>
    public static Stream GetC14nSignedInfo(this PackageDigitalSignature signature)
    {
        if (signature.Signature?.SignedInfo is null)
        {
            throw new InvalidOperationException("Package not signed, Signature.SignedInfo is null");
        }

        // Load the SignedInfo XML into an XmlDocument
        var signatureXml = signature.Signature.GetXml();
        var signedInfoXmlDoc = PreProcessElementInput(
            signature.Signature.SignedInfo.GetXml(),
            XmlResolver.ThrowingResolver,
            signatureXml.BaseURI
        );

        // Load the SignedInfo XML into a C14N transform
        var c14nMethodTransform = signature.Signature.SignedInfo.CanonicalizationMethodObject;
        c14nMethodTransform.Resolver = XmlResolver.ThrowingResolver;
        c14nMethodTransform.LoadInput(signedInfoXmlDoc);

        // Return the C14N canonicalized representation of the SignedInfo XML
        return (Stream)c14nMethodTransform.GetOutput(typeof(Stream));
    }

    /// <summary>
    /// Based on internal PreProcessElementInput method from System.Security.Cryptography.Xml.Utils
    /// </summary>
    private static XmlDocument PreProcessElementInput(
        XmlElement elem,
        XmlResolver xmlResolver,
        string? baseUri
    )
    {
        // NOTE:
        // The MyXmlDocument stuff from the original implementation was removed. It's not required for our use case.

        var doc = new XmlDocument { PreserveWhitespace = true };

        // Normalize the document
        using (var stringReader = new StringReader(elem.OuterXml))
        {
            var settings = new XmlReaderSettings
            {
                XmlResolver = xmlResolver,
                DtdProcessing = DtdProcessing.Parse,
                // Note: From constants in System.Security.Cryptography.Xml.Utils class
                MaxCharactersFromEntities = (long)1e7,
                MaxCharactersInDocument = 0
            };
            var reader = XmlReader.Create(stringReader, settings, baseUri);
            doc.Load(reader);
        }

        return doc;
    }
}
