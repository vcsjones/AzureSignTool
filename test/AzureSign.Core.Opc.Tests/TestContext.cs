using AzureSign.Core.Opc.Tests.TestData;
using System.Reflection;

namespace AzureSign.Core.Opc.Tests;

/// <summary>
/// Provides context for test execution and synthetic test data management.
/// </summary>
public static class TestContext
{
    /// <summary>
    /// Gets the directory containing test assets.
    /// </summary>
    public static string TestAssetsDirectory
    {
        get
        {
            var assemblyLocation = Assembly.GetExecutingAssembly().Location;
            var assemblyDirectory = Path.GetDirectoryName(assemblyLocation)!;
            return Path.Combine(assemblyDirectory, "TestAssets");
        }
    }

    /// <summary>
    /// Creates a temporary HLKX file for testing purposes.
    /// </summary>
    /// <param name="type">The type of HLKX file to create</param>
    /// <returns>Path to the temporary file</returns>
    public static string CreateTempHlkxFile(HlkxTestFileType type = HlkxTestFileType.Minimal)
    {
        var tempFile = Path.GetTempFileName();
        
        switch (type)
        {
            case HlkxTestFileType.Minimal:
                SyntheticHlkxGenerator.CreateMinimalHlkx(tempFile);
                break;
            case HlkxTestFileType.PreSigned:
                SyntheticHlkxGenerator.CreatePreSignedHlkx(tempFile);
                break;
            case HlkxTestFileType.Invalid:
                SyntheticHlkxGenerator.CreateInvalidHlkx(tempFile);
                break;
        }
        
        return tempFile;
    }
}

/// <summary>
/// Types of synthetic HLKX test files that can be created.
/// </summary>
public enum HlkxTestFileType
{
    /// <summary>
    /// A minimal but valid unsigned HLKX file
    /// </summary>
    Minimal,
    
    /// <summary>
    /// A pre-signed HLKX file with synthetic signature data
    /// </summary>
    PreSigned,
    
    /// <summary>
    /// An invalid HLKX file for error testing
    /// </summary>
    Invalid
}