using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace AzureSign.Opc.Extensions;

internal static class ZipArchiveExtension
{
    public static void AddBinaryEntry(
        this ZipArchive packageZip,
        string newEntryPath,
        ReadOnlySpan<byte> buffer
    )
    {
        var newZipEntry = packageZip.CreateEntry(newEntryPath);
        using var zipEntryStream = newZipEntry.Open();
        zipEntryStream.Write(buffer);
    }

    public static void AddXElementEntry(
        this ZipArchive packageZip,
        string newEntryPath,
        XElement xElement
    )
    {
        var newZipEntry = packageZip.CreateEntry(newEntryPath);
        using var zipEntryStream = newZipEntry.Open();
        xElement.Save(zipEntryStream, SaveOptions.DisableFormatting);
    }

    public static ZipArchiveEntry GetOpcDigitalSignatureEntry(
        this ZipArchive archive,
        string directory,
        string extension
    )
    {
        var entryRegex = new Regex(
            $"^package/services/digital-signature/{directory.Trim('/')}/([a-zA-Z0-9\\-\\.]*)"
        );
        return archive
            .Entries.Where(e =>
                entryRegex.IsMatch(e.FullName) && e.Name.EndsWith('.' + extension.TrimStart('.'))
            )
            .Single();
    }

    public static (string OldCertPath, string NewCertPath) ReplaceOpcEmbeddedCertificate(
        this ZipArchive packageZip,
        X509Certificate2 publicCertificate
    )
    {
        // Remove the old certificate entry
        var oldCertificateEntry = packageZip.GetOpcDigitalSignatureEntry("certificate", ".cer");
        var oldCertificatePath = oldCertificateEntry.FullName;
        oldCertificateEntry.Delete();

        // Add thew new certificate data, using the certificate serial as the file name
        var newCertificateSerial = publicCertificate.SerialNumber;
        var newCertificatePath =
            $"package/services/digital-signature/certificate/{newCertificateSerial}.cer";
        var newCertificateData = publicCertificate.Export(X509ContentType.Cert);
        packageZip.AddBinaryEntry(newCertificatePath, newCertificateData);

        return (oldCertificatePath, newCertificatePath);
    }

    public static void ReplaceOpcRelationshipTarget(
        this ZipArchive packageZip,
        string oldCertPath,
        string newCertPath
    )
    {
        // Get the current relationship XML, then delete the old entry
        var oldSignatureRelsEntry = packageZip.GetOpcDigitalSignatureEntry(
            "xml-signature/_rels",
            ".rels"
        );
        var signatureRelsEntryPath = oldSignatureRelsEntry.FullName;
        var signatureRelsXml = GetXElement(oldSignatureRelsEntry);
        oldSignatureRelsEntry.Delete();

        // Replace the relationship target in the old entry
        var relationshipElement = signatureRelsXml
            .Descendants()
            .Where(e => e.Name.LocalName == "Relationship")
            .First(e =>
                e.Attributes().Any(a => a.Name == "Target" && a.Value.Contains(oldCertPath))
            );
        relationshipElement.SetAttributeValue("Target", '/' + newCertPath);

        // Add the new relationship entry to the package
        packageZip.AddXElementEntry(signatureRelsEntryPath, signatureRelsXml);
    }

    public static void ReplaceOpcSignatureValue(
        this ZipArchive packageZip,
        ReadOnlySpan<byte> newSignature
    )
    {
        // Get the current signature XML, then delete the old entry
        var oldSignatureEntry = packageZip.GetOpcDigitalSignatureEntry("xml-signature", ".psdsxs");
        var signatureEntryPath = oldSignatureEntry.FullName;
        var signatureXml = GetXElement(oldSignatureEntry);
        oldSignatureEntry.Delete();

        // Update the SignatureValue in the old Signature
        var signedValueElement = signatureXml
            .Descendants()
            .Single(e => e.Name.LocalName == "SignatureValue");
        signedValueElement.Value = Convert.ToBase64String(newSignature);

        // Add the patched signature entry to the package
        packageZip.AddXElementEntry(signatureEntryPath, signatureXml);
    }

    private static XElement GetXElement(ZipArchiveEntry zipEntry)
    {
        using var zipEntryStream = zipEntry.Open();
        return XElement.Load(zipEntryStream);
    }
}
