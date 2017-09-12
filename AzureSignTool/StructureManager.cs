using System;
using System.Runtime.InteropServices;

namespace AzureSignTool
{
    public sealed class PrimitiveStructureOutManager : IDisposable
    {
        private readonly Action<IntPtr> _cleanup;
        private IntPtr _ptr;

        private PrimitiveStructureOutManager(Action<IntPtr> cleanup)
        {
            _cleanup = cleanup;
            _ptr = Marshal.AllocHGlobal(Marshal.SizeOf<IntPtr>());
            Marshal.WriteIntPtr(_ptr, IntPtr.Zero);
        }

        public static PrimitiveStructureOutManager Create<T>(Func<IntPtr, T> cleanup) => new PrimitiveStructureOutManager(i => cleanup(i));
        public static PrimitiveStructureOutManager Create() => new PrimitiveStructureOutManager(null);

        public IntPtr Handle => _ptr;
        public IntPtr? Object
        {
            get
            {
                if (_ptr == IntPtr.Zero)
                {
                    return null;
                }
                var contents = Marshal.ReadIntPtr(_ptr);
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
            Marshal.FreeHGlobal(_ptr);
            _ptr = IntPtr.Zero;
        }
    }
}
