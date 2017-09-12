using System;
using System.Runtime.InteropServices;

namespace AzureSignTool
{
    public static class NativeConstants
    {
        static NativeConstants()
        {
            //This memory is intended to live for the duration of the process. Don't free it.
            ZeroDWORD = Marshal2.AllocHGlobal<uint>();
            Marshal.WriteInt32(ZeroDWORD, 0);
        }

        public static IntPtr ZeroDWORD { get; }
    }
}
