using System;
using System.IO;

namespace AzureSignTool
{
    internal enum SipKind
    {
        None,
        Appx
    }

    internal class SipExtensionFactory
    {
        public static SipKind GetSipKind(ReadOnlySpan<char> filePath)
        {
            var extension = Path.GetExtension(filePath);
            if (extension.Equals(".appx", StringComparison.OrdinalIgnoreCase))
            {
                return SipKind.Appx;
            }
            if (extension.Equals(".eappx", StringComparison.OrdinalIgnoreCase))
            {
                return SipKind.Appx;
            }
            if (extension.Equals(".appxbundle", StringComparison.OrdinalIgnoreCase))
            {
                return SipKind.Appx;
            }
            if (extension.Equals(".eappxbundle", StringComparison.OrdinalIgnoreCase))
            {
                return SipKind.Appx;
            }
            return SipKind.None;
        }
    }
}