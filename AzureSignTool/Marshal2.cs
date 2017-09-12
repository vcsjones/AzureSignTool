using System;
using System.Runtime.InteropServices;

namespace AzureSignTool
{
    internal static class Marshal2
    {
        public static IntPtr AllocHGlobal<TStruct>() where TStruct:struct => Marshal.AllocHGlobal(Marshal.SizeOf<TStruct>());

        public static void DestroyAndFreeHGlobal<TStructure>(ref IntPtr ptr) where TStructure : struct
        {
            if (ptr != IntPtr.Zero)
            {
                Marshal.DestroyStructure<TStructure>(ptr);
                Marshal.FreeHGlobal(ptr);
                ptr = IntPtr.Zero;
            }
        }
    }
}
