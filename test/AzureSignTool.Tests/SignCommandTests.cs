using System;
using System.IO;
using Xunit;

namespace AzureSignTool.Tests;

public class SignCommandTests
{
    [Fact]
    public void AllFiles_WithAbsoluteGlobPath_FindsFileCorrectly()
    {
        var tempDirectory = Path.Combine(Path.GetTempPath(), $"absolute-glob-test-{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDirectory);
        var testFilePath = Path.Combine(tempDirectory, "file-to-sign.txt");
        File.WriteAllText(testFilePath, "content");

        var command = new SignCommand();
        var absoluteGlobPattern = Path.Combine(tempDirectory, "**", "*.txt");
        command.Files.Add(absoluteGlobPattern);

        try
        {
            var foundFiles = command.AllFiles;
            var foundFile = Assert.Single(foundFiles);
            Assert.Equal(Path.GetFullPath(testFilePath), foundFile, ignoreCase: true);
        }
        finally
        {
            if (Directory.Exists(tempDirectory))
                Directory.Delete(tempDirectory, recursive: true);
        }
    }

    [Fact]
    public void AllFiles_WithSingleAbsoluteExistingFile_ReturnsOneFile()
    {
        var tempFilePath = Path.Combine(Path.GetTempPath(), $"single-file-test-{Guid.NewGuid()}.tmp");
        File.WriteAllText(tempFilePath, "content");

        var command = new SignCommand();
        command.Files.Add(tempFilePath);

        try
        {
            var foundFiles = command.AllFiles;
            var foundFile = Assert.Single(foundFiles);
            Assert.Equal(Path.GetFullPath(tempFilePath), foundFile, ignoreCase: true);
        }
        finally
        {
            if (File.Exists(tempFilePath)) 
                File.Delete(tempFilePath);
        }
    }

    [Fact]
    public void AllFiles_ShouldIncludeExplicitPath_WhenFileDoesNotExist()
    {
        var command = new SignCommand();
        var nonExistentFilePath = Path.GetFullPath(Path.Combine("non", "existent", "path", $"file-{Guid.NewGuid()}.dll"));

        command.Files.Add(nonExistentFilePath);

        var foundFiles = command.AllFiles;

        var foundFile = Assert.Single(foundFiles);
        Assert.Equal(nonExistentFilePath, foundFile, ignoreCase: true);
    }

    [Fact]
    public void AllFiles_ShouldIncludeExplicitPath_WhenFileExists()
    {
        var tempFile = Path.GetTempFileName();
        var command = new SignCommand();
        command.Files.Add(tempFile);

        try
        {
            var foundFiles = command.AllFiles;
            var foundFile = Assert.Single(foundFiles);
            Assert.Equal(Path.GetFullPath(tempFile), foundFile, ignoreCase: true);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public void AllFiles_ShouldReturnEmpty_WhenGlobMatchesNoFiles()
    {
        var tempDirectory = Path.Combine(Path.GetTempPath(), $"empty-glob-test-{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDirectory);

        var command = new SignCommand();
        command.Files.Add(Path.Combine(tempDirectory, "*.nomatchtype"));

        try
        {
            var foundFiles = command.AllFiles;
            Assert.Empty(foundFiles);
        }
        finally
        {
            if (Directory.Exists(tempDirectory))
                Directory.Delete(tempDirectory, true);
        }
    }

    [Fact]
    public void AllFiles_ShouldReturnCombinedSet_ForMixedInputs()
    {
        var nonExistentFilePath = Path.GetFullPath(Path.Combine("c:", "path", "to", $"non-existent-file-{Guid.NewGuid()}.txt"));

        var tempDirectory = Path.Combine(Path.GetTempPath(), $"mixed-test-{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDirectory);
        var globbedFilePath = Path.Combine(tempDirectory, "app.exe");
        File.WriteAllText(globbedFilePath, "content");

        var command = new SignCommand();
        command.Files.Add(nonExistentFilePath);
        command.Files.Add(Path.Combine(tempDirectory, "*.exe"));

        try
        {
            var foundFiles = command.AllFiles;
            Assert.Equal(2, foundFiles.Count);
            Assert.Contains(nonExistentFilePath, foundFiles, StringComparer.OrdinalIgnoreCase);
            Assert.Contains(Path.GetFullPath(globbedFilePath), foundFiles, StringComparer.OrdinalIgnoreCase);
        }
        finally
        {
            if (Directory.Exists(tempDirectory))
                Directory.Delete(tempDirectory, true);
        }
    }
}
