using System.IO.Compression;
using System.Text;

namespace AzureSign.Core.Opc.Tests.TestData;

/// <summary>
/// Generates synthetic HLKX files for testing without using actual internal data.
/// </summary>
public static class SyntheticHlkxGenerator
{
    /// <summary>
    /// Creates a minimal but valid HLKX structure for testing.
    /// </summary>
    public static void CreateMinimalHlkx(string filePath)
    {
        // Use temporary file approach to avoid ZIP entry length issues
        var tempFilePath = Path.GetTempFileName();
        try
        {
            using (var fileStream = File.Create(tempFilePath))
            using (var zip = new ZipArchive(fileStream, ZipArchiveMode.Create))
            {
                // Create [Content_Types].xml
                CreateContentTypesFile(zip);
                
                // Create _rels/.rels  
                CreateRootRelationshipsFile(zip);
                
                // Create synthetic HCK data parts
                CreateSyntheticHckData(zip);
            }
            
            // Copy to final destination
            File.Copy(tempFilePath, filePath, true);
        }
        finally
        {
            if (File.Exists(tempFilePath))
                File.Delete(tempFilePath);
        }
    }

    /// <summary>
    /// Creates a pre-signed HLKX for testing signature verification.
    /// </summary>
    public static void CreatePreSignedHlkx(string filePath)
    {
        // Use temporary file approach to avoid ZIP entry length issues
        var tempFilePath = Path.GetTempFileName();
        try
        {
            using (var fileStream = File.Create(tempFilePath))
            using (var zip = new ZipArchive(fileStream, ZipArchiveMode.Create))
            {
                // Create basic structure
                CreateContentTypesFileWithSignatures(zip);
                CreateRootRelationshipsFileWithSignatures(zip);
                CreateSyntheticHckData(zip);
                
                // Create synthetic signature parts
                CreateSyntheticSignatureParts(zip);
            }
            
            // Copy to final destination
            File.Copy(tempFilePath, filePath, true);
        }
        finally
        {
            if (File.Exists(tempFilePath))
                File.Delete(tempFilePath);
        }
    }

    private static void CreateContentTypesFile(ZipArchive zip)
    {
        var entry = zip.CreateEntry("[Content_Types].xml");
        using (var stream = entry.Open())
        using (var writer = new StreamWriter(stream, Encoding.UTF8))
        {
            writer.Write(@"<?xml version=""1.0"" encoding=""utf-8""?>
<Types xmlns=""http://schemas.openxmlformats.org/package/2006/content-types"">
  <Default Extension=""rels"" ContentType=""application/vnd.openxmlformats-package.relationships+xml"" />
  <Default Extension=""xml"" ContentType=""application/octet"" />
  <Default Extension=""txt"" ContentType=""application/octet"" />
  <Override PartName=""/hck/data/synthetic-data-1"" ContentType=""application/octet"" />
  <Override PartName=""/hck/data/synthetic-data-2"" ContentType=""application/octet"" />
</Types>");
        }
    }

    private static void CreateContentTypesFileWithSignatures(ZipArchive zip)
    {
        var entry = zip.CreateEntry("[Content_Types].xml");
        using (var stream = entry.Open())
        using (var writer = new StreamWriter(stream, Encoding.UTF8))
        {
            writer.Write(@"<?xml version=""1.0"" encoding=""utf-8""?>
<Types xmlns=""http://schemas.openxmlformats.org/package/2006/content-types"">
  <Default Extension=""rels"" ContentType=""application/vnd.openxmlformats-package.relationships+xml"" />
  <Default Extension=""xml"" ContentType=""application/octet"" />
  <Default Extension=""txt"" ContentType=""application/octet"" />
  <Default Extension=""psdsor"" ContentType=""application/vnd.openxmlformats-package.digital-signature-origin"" />
  <Default Extension=""psdsxs"" ContentType=""application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml"" />
  <Default Extension=""cer"" ContentType=""application/vnd.openxmlformats-package.digital-signature-certificate"" />
  <Override PartName=""/hck/data/synthetic-data-1"" ContentType=""application/octet"" />
  <Override PartName=""/hck/data/synthetic-data-2"" ContentType=""application/octet"" />
</Types>");
        }
    }

    private static void CreateRootRelationshipsFile(ZipArchive zip)
    {
        var entry = zip.CreateEntry("_rels/.rels");
        using (var stream = entry.Open())
        using (var writer = new StreamWriter(stream, Encoding.UTF8))
        {
            writer.Write(@"<?xml version=""1.0"" encoding=""utf-8""?>
<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships"">
  <Relationship Type=""http://microsoft.com/schemas/windows/kits/hardware/2010/packageinfo"" Target=""/hck/data/PackageInfo.xml"" Id=""R12345678"" />
  <Relationship Type=""http://microsoft.com/schemas/windows/kits/hardware/2010/streamdata"" Target=""/hck/data/synthetic-data-1"" Id=""R87654321"" />
  <Relationship Type=""http://microsoft.com/schemas/windows/kits/hardware/2010/coredata"" Target=""/hck/data/synthetic-data-2"" Id=""R11111111"" />
  <Relationship Type=""http://microsoft.com/shcemas/windows/kits/hardware/2010/packageinfo"" Target=""/hck/data/PackageInfo.xml"" Id=""R99999999"" />
</Relationships>");
        }
    }

    private static void CreateRootRelationshipsFileWithSignatures(ZipArchive zip)
    {
        var entry = zip.CreateEntry("_rels/.rels");
        using (var stream = entry.Open())
        using (var writer = new StreamWriter(stream, Encoding.UTF8))
        {
            writer.Write(@"<?xml version=""1.0"" encoding=""utf-8""?>
<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships"">
  <Relationship Type=""http://microsoft.com/schemas/windows/kits/hardware/2010/packageinfo"" Target=""/hck/data/PackageInfo.xml"" Id=""R12345678"" />
  <Relationship Type=""http://microsoft.com/schemas/windows/kits/hardware/2010/streamdata"" Target=""/hck/data/synthetic-data-1"" Id=""R87654321"" />
  <Relationship Type=""http://microsoft.com/schemas/windows/kits/hardware/2010/coredata"" Target=""/hck/data/synthetic-data-2"" Id=""R11111111"" />
  <Relationship Type=""http://microsoft.com/shcemas/windows/kits/hardware/2010/packageinfo"" Target=""/hck/data/PackageInfo.xml"" Id=""R99999999"" />
  <Relationship Type=""http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin"" Target=""/package/services/digital-signature/origin.psdsor"" Id=""RSig12345"" />
</Relationships>");
        }
    }

    private static void CreateSyntheticHckData(ZipArchive zip)
    {
        // Create PackageInfo.xml with synthetic hardware certification data
        var packageInfoEntry = zip.CreateEntry("hck/data/PackageInfo.xml");
        using (var stream = packageInfoEntry.Open())
        using (var writer = new StreamWriter(stream, Encoding.UTF8))
        {
            writer.Write(@"<?xml version=""1.0"" encoding=""utf-8""?>
<Package Type=""SubmissionPackage"" KitVersion=""10.0.0.0"" PackageVersion=""1.0.0.0"" PackageFormatVersion=""2.0.0.0"" IsWindowsDriverProject=""False"" CreationDate=""2024-01-01 12:00 PM"" BuildBranch=""test_branch"" FullBuildName=""test_branch.1.0.0.0.240101-1200"">
  <Project Name=""SyntheticTestProject"" CreationDate=""2024-01-01 9:00 AM"">
    <ProductInstances>
      <ProductInstance Status=""Pass"">
        <OperatingSystem Architecture=""X64"">
          <Codes>
            <Code Name=""WINDOWS_v100_SERVER_X64_TEST"" />
          </Codes>
        </OperatingSystem>
        <Features>
          <Feature FullName=""Device.DevFund.TestFeature"" />
        </Features>
        <ProductTypes />
        <Targets>
          <Target Key=""TEST\DEVICE\1"" DriverStatus=""ProvidedDrivers"" Name=""Synthetic Test Device"" TargetType=""Device"">
            <Driver Id=""synthetic-driver-id"" ReplacesId="""">
              <OperatingSystems>
                <OperatingSystem Architecture=""X64"" Code=""WINDOWS_v100_SERVER_X64_TEST"" />
              </OperatingSystems>
              <Locales>
                <Locale Name=""English"" />
              </Locales>
            </Driver>
          </Target>
        </Targets>
      </ProductInstance>
    </ProductInstances>
    <TestRollup Passed=""5"" Failed=""0"" NotRun=""0"" />
  </Project>
</Package>");
        }

        // Create synthetic binary data files
        var dataEntry1 = zip.CreateEntry("hck/data/synthetic-data-1");
        using (var stream = dataEntry1.Open())
        {
            var syntheticData = Encoding.UTF8.GetBytes("This is synthetic test data for stream data testing. It represents hardware certification test results but contains no actual internal data.");
            stream.Write(syntheticData);
        }

        var dataEntry2 = zip.CreateEntry("hck/data/synthetic-data-2");
        using (var stream = dataEntry2.Open())
        {
            var syntheticData = Encoding.UTF8.GetBytes("This is synthetic core data for testing. It simulates the structure of hardware lab kit data without containing any real certification information.");
            stream.Write(syntheticData);
        }

        // Create synthetic telemetry data
        var telemetryEntry = zip.CreateEntry("hck/telemetry/SyntheticTelemetry.txt");
        using (var stream = telemetryEntry.Open())
        using (var writer = new StreamWriter(stream, Encoding.UTF8))
        {
            writer.Write("Synthetic telemetry data for testing purposes.\nTimestamp: 2024-01-01T12:00:00Z\nTest: SyntheticTest\nResult: Pass");
        }
    }

    private static void CreateSyntheticSignatureParts(ZipArchive zip)
    {
        // Create origin marker
        var originEntry = zip.CreateEntry("package/services/digital-signature/origin.psdsor");
        using (var stream = originEntry.Open())
        {
            // Empty file as per OPC spec
        }

        // Create synthetic XML signature
        var signatureId = "synthetic12345";
        var xmlSigEntry = zip.CreateEntry($"package/services/digital-signature/xml-signature/{signatureId}.psdsxs");
        using (var stream = xmlSigEntry.Open())
        using (var writer = new StreamWriter(stream, Encoding.UTF8))
        {
            writer.Write($@"<?xml version=""1.0"" encoding=""utf-8"" standalone=""yes""?>
<Signature Id=""SignatureIdValue"" xmlns=""http://www.w3.org/2000/09/xmldsig#"">
  <SignedInfo>
    <CanonicalizationMethod Algorithm=""http://www.w3.org/TR/2001/REC-xml-c14n-20010315"" />
    <SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" />
    <Reference URI=""#idPackageObject"" Type=""http://www.w3.org/2000/09/xmldsig#Object"">
      <DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" />
      <DigestValue>SyntheticDigestValueForTesting==</DigestValue>
    </Reference>
  </SignedInfo>
  <SignatureValue>SyntheticSignatureValueForTestingPurposesOnly==</SignatureValue>
  <Object Id=""idPackageObject"">
    <Manifest>
      <Reference URI=""/hck/data/synthetic-data-1?ContentType=application/octet"">
        <DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" />
        <DigestValue>SyntheticHash1==</DigestValue>
      </Reference>
    </Manifest>
    <SignatureProperties>
      <SignatureProperty Id=""idSignatureTime"" Target=""#SignatureIdValue"">
        <SignatureTime xmlns=""http://schemas.openxmlformats.org/package/2006/digital-signature"">
          <Format>YYYY-MM-DDThh:mm:ss.sTZD</Format>
          <Value>2024-01-01T12:00:00.0+00:00</Value>
        </SignatureTime>
      </SignatureProperty>
    </SignatureProperties>
  </Object>
</Signature>");
        }

        // Create synthetic certificate
        var certHash = "SYNTHETICCERTHASH123456789ABCDEF";
        var certEntry = zip.CreateEntry($"package/services/digital-signature/certificate/{certHash}.cer");
        using (var stream = certEntry.Open())
        {
            // Create a minimal synthetic certificate-like structure
            var syntheticCert = Encoding.UTF8.GetBytes("SYNTHETIC-CERT-DATA-FOR-TESTING-NOT-A-REAL-CERTIFICATE");
            stream.Write(syntheticCert);
        }

        // Create origin relationships
        var originRelsEntry = zip.CreateEntry("package/services/digital-signature/_rels/origin.psdsor.rels");
        using (var stream = originRelsEntry.Open())
        using (var writer = new StreamWriter(stream, Encoding.UTF8))
        {
            writer.Write($@"<?xml version=""1.0"" encoding=""utf-8""?>
<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships"">
  <Relationship Type=""http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature"" Target=""/package/services/digital-signature/xml-signature/{signatureId}.psdsxs"" Id=""R{signatureId}"" />
</Relationships>");
        }

        // Create signature relationships
        var sigRelsEntry = zip.CreateEntry($"package/services/digital-signature/xml-signature/_rels/{signatureId}.psdsxs.rels");
        using (var stream = sigRelsEntry.Open())
        using (var writer = new StreamWriter(stream, Encoding.UTF8))
        {
            writer.Write($@"<?xml version=""1.0"" encoding=""utf-8""?>
<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships"">
  <Relationship Type=""http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/certificate"" Target=""/package/services/digital-signature/certificate/{certHash}.cer"" Id=""R{certHash}"" />
</Relationships>");
        }
    }

    /// <summary>
    /// Creates an invalid HLKX file for testing error handling.
    /// </summary>
    public static void CreateInvalidHlkx(string filePath)
    {
        // Create a file that looks like HLKX but is corrupted
        File.WriteAllText(filePath, "This is not a valid HLKX file - it's just text pretending to be a ZIP archive");
    }
}