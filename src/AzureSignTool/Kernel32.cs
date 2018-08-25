using System;
using System.Runtime.InteropServices;

namespace AzureSignTool
{
    internal static class Kernel32
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
        internal static extern IntPtr LoadLibraryW([MarshalAs(UnmanagedType.LPWStr)] string path);
    }
}
