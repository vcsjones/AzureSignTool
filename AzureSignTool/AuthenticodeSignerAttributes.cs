using AzureSignTool.Interop;
using System;
using System.Runtime.InteropServices;

namespace AzureSignTool
{
    public sealed class AuthenticodeSignerAttributes : IDisposable
    {
        private IntPtr _descriptionPtr;
        private IntPtr _urlPtr;
        private IntPtr _handle;

        public AuthenticodeSignerAttributes(string description, string url)
        {
            _descriptionPtr = Marshal.StringToHGlobalUni(description ?? "");
            _urlPtr = Marshal.StringToHGlobalUni(url ?? "");
            var authCodeStructure = new SIGNER_ATTR_AUTHCODE(
                 pwszName: _descriptionPtr,
                 pwszInfo: _urlPtr
            );
            _handle = Marshal2.AllocHGlobal<SIGNER_ATTR_AUTHCODE>();
            Marshal.StructureToPtr(authCodeStructure, _handle, false);
        }

        public IntPtr Handle => _handle;

        public void Dispose() => Dispose(true);
        ~AuthenticodeSignerAttributes() => Dispose(false);

        private void Dispose(bool disposing)
        {
            GC.SuppressFinalize(this);
            if (_handle != IntPtr.Zero)
            { 
                Marshal.DestroyStructure<SIGNER_ATTR_AUTHCODE>(_handle);
                Marshal.FreeHGlobal(_handle);
            }
            Marshal.FreeHGlobal(_descriptionPtr);
            Marshal.FreeHGlobal(_urlPtr);
            _handle = IntPtr.Zero;
            _descriptionPtr = IntPtr.Zero;
            _urlPtr = IntPtr.Zero;
        }
    }
}
