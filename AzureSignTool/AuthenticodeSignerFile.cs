using AzureSignTool.Interop;
using System;
using System.Runtime.InteropServices;

namespace AzureSignTool
{
    public class AuthenticodeSignerFile : IDisposable
    {
        private IntPtr _filePathPtr;
        private GCHandle _handle;

        public AuthenticodeSignerFile(string filePath)
        {
            _filePathPtr = Marshal.StringToHGlobalUni(filePath);
            var signerFileInfo = new SIGNER_FILE_INFO(
                pwszFileName: _filePathPtr,
                hFile: default
           );
            _handle = GCHandle.Alloc(signerFileInfo, GCHandleType.Pinned);
        }

        public IntPtr Handle => _handle.AddrOfPinnedObject();

        public void Dispose()
        {
            _handle.Free();
            Marshal.FreeHGlobal(_filePathPtr);
        }
    }
}
