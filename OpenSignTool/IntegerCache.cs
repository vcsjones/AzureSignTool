using System;
using System.Runtime.InteropServices;

namespace OpenSignTool
{
    public static class IntegerCache
    {
        static IntegerCache()
        {
            //This memory is intended to live for the duration of the process. Don't free it.
            Zero = Marshal.AllocHGlobal(Marshal.SizeOf<uint>());
            Marshal.WriteInt32(Zero, 0);
        }

        public static IntPtr Zero { get; }
    }
}
