using System;
using System.Runtime.InteropServices;

namespace AzureSignTool
{
    public sealed class PrimitiveStructureOutManager : IDisposable
    {
        private readonly Action<IntPtr> _cleanup;
        private IntPtr ptr;

        private PrimitiveStructureOutManager(Action<IntPtr> cleanup)
        {
            _cleanup = cleanup;
            ptr = Marshal.AllocHGlobal(Marshal.SizeOf<IntPtr>());
            Marshal.WriteIntPtr(ptr, IntPtr.Zero);
        }

        public static PrimitiveStructureOutManager Create<T>(Func<IntPtr, T> cleanup) => new PrimitiveStructureOutManager(i => cleanup(i));
        public static PrimitiveStructureOutManager Create() => new PrimitiveStructureOutManager(null);

        public IntPtr Handle => ptr;
        public IntPtr? Object
        {
            get
            {
                if (ptr == IntPtr.Zero)
                {
                    return null;
                }
                var contents = Marshal.ReadIntPtr(ptr);
                if (contents == IntPtr.Zero)
                {
                    return null;
                }
                return contents;
            }
        }

        public void Dispose()
        {
            if (Object.HasValue && _cleanup != null)
            {
                _cleanup(Object.Value);
            }
            Marshal.FreeHGlobal(ptr);
            ptr = IntPtr.Zero;
        }
    }
}
