using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace AzureSignTool
{
    internal static class Marshal2
    {
        public static IntPtr AllocHGlobal<TStruct>() where TStruct:struct => Marshal.AllocHGlobal(Marshal.SizeOf<TStruct>());

        public static void DestroyAndFreeHGlobal<TStructure>(ref IntPtr ptr) where TStructure : struct
        {
            var cleanupPtr = Interlocked.Exchange(ref ptr, IntPtr.Zero);
            if (cleanupPtr != IntPtr.Zero)
            {
                Marshal.DestroyStructure<TStructure>(cleanupPtr);
                Marshal.FreeHGlobal(cleanupPtr);
            }
        }
    }
}
