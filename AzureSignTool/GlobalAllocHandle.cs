using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace AzureSignTool
{
    internal class GlobalAllocHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public GlobalAllocHandle() : base(true)
        {
        }

        public static GlobalAllocHandle Alloc(int size)
        {
            var ptr = Marshal.AllocHGlobal(size);
            var globalHandle = new GlobalAllocHandle();
            globalHandle.SetHandle(ptr);
            return globalHandle;
        }

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }
}
