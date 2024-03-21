namespace ReSignMsixBundle.BusinessLogic;

internal static class X64ExePathFinder
{
    /// <summary>Searches for the first match of a file in <see cref="Environment.SpecialFolder.ProgramFilesX86"/>.</summary>
    /// <param name="file">The file.</param>
    /// <param name="logger">The logger.</param>
    /// <returns>A string.</returns>
    public static string Find(string file, ILogger logger)
    {
        var programFilesPath = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var path = Directory
            .EnumerateFiles(programFilesPath, file, new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true })
            .Where(IsNativeX64File)
            .OrderByDescending(File.GetCreationTimeUtc)
            .FirstOrDefault(string.Empty);
        if (string.IsNullOrEmpty(path))
        {
            logger.LogCritical("Executable {File} not found under {ProgramFilesPath}, or incorrect processor architecture",
                file,
                programFilesPath);
        }

        return path;
    }

    private static bool IsNativeX64File(string filePath)
    {
        using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        using var reader = new BinaryReader(fileStream);
        fileStream.Seek(0x3C, SeekOrigin.Begin);
        var peOffset = reader.ReadInt32();
        fileStream.Seek(peOffset, SeekOrigin.Begin);
        var peHead = reader.ReadUInt32();

        if (peHead != 0x00004550)
        {
            return false;
        }

        fileStream.Seek(peOffset + 4, SeekOrigin.Begin);
        var architecture = reader.ReadUInt16();

        return architecture == 0x8664;
    }
}
