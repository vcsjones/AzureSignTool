using System;
using System.Runtime.InteropServices;

namespace AzureSignTool
{
    // This acts as an "out" handler that works on structure fields.
    public class StructureOutManager<T> : PrimitiveStructureOutManager where T:struct
    {

        public T? Value
        {
            get
            {
                if (!Object.HasValue)
                {
                    return null;
                }
                return Marshal.PtrToStructure<T>(Object.Value);
            }
        }
    }

    public class PrimitiveStructureOutManager : IDisposable
    {
        protected IntPtr ptr;

        public PrimitiveStructureOutManager()
        {
            ptr = Marshal.AllocHGlobal(Marshal.SizeOf<IntPtr>());
            Marshal.WriteIntPtr(ptr, IntPtr.Zero);
        }

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
            Marshal.FreeHGlobal(ptr);
            ptr = IntPtr.Zero;
        }
    }
}
