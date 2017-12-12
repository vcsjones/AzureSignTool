using AzureSignTool.Interop;
using System;
using System.Runtime.InteropServices;
using System.Threading;

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
            var cleanupHandle = Interlocked.Exchange(ref _handle, IntPtr.Zero);
            if (cleanupHandle != IntPtr.Zero)
            { 
                Marshal.DestroyStructure<SIGNER_ATTR_AUTHCODE>(cleanupHandle);
                Marshal.FreeHGlobal(cleanupHandle);
            }
            var cleanupDescriptionPtr = Interlocked.Exchange(ref _descriptionPtr, IntPtr.Zero);
            var cleanupUrlPtr = Interlocked.Exchange(ref _urlPtr, IntPtr.Zero);
            if (cleanupDescriptionPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(cleanupDescriptionPtr);
            }
            if (cleanupUrlPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(cleanupUrlPtr);
            }
        }
    }
}
