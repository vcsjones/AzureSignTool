using OpenSignTool.Interop;
using System;
using System.Runtime.InteropServices;

namespace OpenSignTool
{
    public class AuthenticodeSignerAttributes : IDisposable
    {
        private IntPtr _authorPtr;
        private IntPtr _urlPtr;
        private GCHandle _handle;

        public AuthenticodeSignerAttributes(string author, string url)
        {
            _authorPtr = Marshal.StringToHGlobalUni(author ?? "");
            _urlPtr = Marshal.StringToHGlobalUni(url ?? "");
            var authCodeStructure = new SIGNER_ATTR_AUTHCODE(
                 pwszName: _authorPtr,
                 pwszInfo: _urlPtr
            );
            _handle = GCHandle.Alloc(authCodeStructure, GCHandleType.Pinned);
        }

        public IntPtr Handle => _handle.AddrOfPinnedObject();

        public void Dispose()
        {
            _handle.Free();
            Marshal.FreeHGlobal(_authorPtr);
            Marshal.FreeHGlobal(_urlPtr);
        }
    }
}
