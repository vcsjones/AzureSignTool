using System.Diagnostics.CodeAnalysis;
using Microsoft.Msix.Utils;
using Microsoft.Msix.Utils.AppxPackagingInterop;
using static Microsoft.Msix.Utils.AppxPackagingInterop.APPX_PACKAGE_EDITOR_UPDATE_PACKAGE_MANIFEST_OPTIONS;

#pragma warning disable IDE0079

namespace ReSignMsixBundle.BusinessLogic;

[SupportedOSPlatform("windows")] internal class AppxPackageEditorWrapper
{
    [SuppressMessage("ReSharper", "SuspiciousTypeConversion.Global")]
    private readonly IAppxPackageEditor _packageEditor = (IAppxPackageEditor)new AppxPackageEditor();

    /// <summary>Updates the package manifest.</summary>
    /// <param name="packagePath">Full pathname of the package file.</param>
    /// <param name="manifestPath">Full pathname of the manifest file.</param>
    public void UpdatePackageManifest(string packagePath, string manifestPath)
    {
        var packageStream = StreamUtils.CreateInputOutputStreamOnFile(packagePath, false);
        var manifestStream = StreamUtils.CreateInputStreamOnFile(manifestPath);
        _packageEditor.UpdatePackageManifest(packageStream,
            manifestStream,
            false,
            APPX_PACKAGE_EDITOR_UPDATE_PACKAGE_MANIFEST_OPTION_SKIP_VALIDATION);
        packageStream.Commit(0);

        Marshal.FinalReleaseComObject(packageStream);
        Marshal.FinalReleaseComObject(manifestStream);
    }
}
