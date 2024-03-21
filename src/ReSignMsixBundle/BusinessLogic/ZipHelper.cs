namespace ReSignMsixBundle.BusinessLogic;

internal class ZipHelper(ILogger logger) : IDisposable
{
    /// <summary>Gets the pathname of the temporary directory.</summary>
    public string TempDirectory { get; } = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

    public void Dispose()
    {
        try
        {
            Directory.Delete(TempDirectory, true);
        }
        catch
        {
            // pass
        }
    }

    /// <summary>Extracts the zip file to a temporary directory.</summary>
    /// <param name="zipFilePath">Full pathname of the zip file.</param>
    /// <param name="cancellationToken">A token that allows processing to be cancelled.</param>
    /// <returns>The extracted files.</returns>
    /// <remarks>Only files that have the .MSIX extension are extracted.</remarks>
    internal List<string> ExtractZipFile(string zipFilePath, CancellationToken cancellationToken)
    {
        List<string> files = [];
        try
        {
            Directory.CreateDirectory(TempDirectory);

            using (var msixBundle = ZipFile.OpenRead(zipFilePath))
            {
                foreach (var entry in msixBundle.Entries)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        Directory.Delete(TempDirectory, true);
                        return [];
                    }

                    if (!string.Equals(Path.GetExtension(entry.Name), ".msix", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var entryDestination = Path.Combine(TempDirectory, Uri.UnescapeDataString(entry.Name));
                    entry.ExtractToFile(entryDestination, true);
                    files.Add(entryDestination);
                }
            }

            logger.LogInformation("MSIX bundle contents extracted to: {TempDirectory} - {Count} files", TempDirectory, files.Count);
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Error extracting MSIX bundle contents. See {TempDirectory}", TempDirectory);
        }

        return files;
    }
}
