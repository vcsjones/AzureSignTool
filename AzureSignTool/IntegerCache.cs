using System;
using System.Runtime.InteropServices;

namespace AzureSignTool
{
    public static class IntegerCache
    {
        static IntegerCache()
        {
            //This memory is intended to live for the duration of the process. Don't free it.
            Zero = Marshal.AllocHGlobal(Marshal.SizeOf<uint>());
            Marshal.WriteInt32(Zero, 0);
            EmptyStringW = Marshal.StringToHGlobalUni("");
            EmptyStringA = Marshal.StringToHGlobalAnsi("");
        }

        public static IntPtr Zero { get; }

        public static IntPtr EmptyStringW { get; }
        public static IntPtr EmptyStringA { get; }
    }
}
