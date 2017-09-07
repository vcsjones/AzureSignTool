using System;
using System.Runtime.InteropServices;

namespace AzureSignTool
{
    public static class NativeConstants
    {
        static NativeConstants()
        {
            //This memory is intended to live for the duration of the process. Don't free it.
            ZeroDWORD = Marshal.AllocHGlobal(Marshal.SizeOf<uint>());
            Marshal.WriteInt32(ZeroDWORD, 0);
            EmptyStringW = Marshal.StringToHGlobalUni("");
            EmptyStringA = Marshal.StringToHGlobalAnsi("");
        }

        public static IntPtr ZeroDWORD { get; }

        public static IntPtr EmptyStringW { get; }
        public static IntPtr EmptyStringA { get; }
    }
}
