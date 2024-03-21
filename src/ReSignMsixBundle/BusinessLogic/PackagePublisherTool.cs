using System.Xml.Linq;

namespace ReSignMsixBundle.BusinessLogic;

[SupportedOSPlatform("windows")] internal sealed class PackagePublisherTool(ILogger logger)
{
    /// <summary>Modify the package publisher in the manifests of a list of MSIX files.</summary>
    /// <param name="msixFiles">The MSIX files.</param>
    /// <param name="publisher">The publisher.</param>
    /// <param name="cancellationToken">A token that allows processing to be cancelled.</param>
    public void ModifyPackagePublisher(ICollection<string> msixFiles, string publisher, CancellationToken cancellationToken)
    {
        var modifiedCount = 0;
        foreach (var msixFile in msixFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ModifyPackagePublisher(msixFile, publisher))
            {
                modifiedCount++;
            }
        }

        logger.LogInformation("Modified {ModifiedCount} of {TotalCount} MSIX files", modifiedCount, msixFiles.Count);
    }

    private bool ModifyPackagePublisher(string msixFile, string publisher)
    {
        var manifestPath = string.Empty;
        using (var zip = ZipFile.OpenRead(msixFile))
        {
            foreach (var entry in zip.Entries)
            {
                if (!entry.Name.Equals("AppxManifest.xml", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                manifestPath = Path.Combine(Path.GetTempPath(), entry.Name);
                entry.ExtractToFile(manifestPath, true);

                if (!ModifyPublisherInManifest(manifestPath, publisher))
                {
                    return false;
                }

                break;
            }
        }

        if (string.IsNullOrEmpty(manifestPath))
        {
            throw new InvalidOperationException($"AppxManifest.xml was not found in {msixFile}");
        }

        new AppxPackageEditorWrapper().UpdatePackageManifest(msixFile, manifestPath);
        return true;
    }

    private bool ModifyPublisherInManifest(string manifestPath, string publisher)
    {
        var xmlDoc = XDocument.Load(manifestPath);
        var publisherAttribute = xmlDoc.Descendants().FirstOrDefault(x => x.Name.LocalName == "Identity")?.Attribute("Publisher");
        if (publisherAttribute == null)
        {
            logger.LogWarning("Could not find Publisher attribute in manifest {ManifestPath}", manifestPath);
            return false;
        }

        publisherAttribute.Value = publisher;
        xmlDoc.Save(manifestPath);
        return true;
    }
}
