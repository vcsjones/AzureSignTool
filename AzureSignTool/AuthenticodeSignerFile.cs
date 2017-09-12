using AzureSignTool.Interop;
using System;
using System.Runtime.InteropServices;

namespace AzureSignTool
{
    public class AuthenticodeSignerFile : IDisposable
    {
        private IntPtr _filePathPtr;
        private IntPtr _handle;

        public AuthenticodeSignerFile(string filePath)
        {
            _filePathPtr = Marshal.StringToHGlobalUni(filePath);
            var signerFileInfo = new SIGNER_FILE_INFO(
                pwszFileName: _filePathPtr,
                hFile: default
           );
            _handle = Marshal2.AllocHGlobal<SIGNER_FILE_INFO>();
            Marshal.StructureToPtr(signerFileInfo, _handle, false);
        }

        public IntPtr Handle => _handle;

        public void Dispose() => Dispose(true);
        ~AuthenticodeSignerFile() => Dispose(false);

        private void Dispose(bool disposing)
        {
            if (_handle != IntPtr.Zero)
            {
                Marshal.DestroyStructure<SIGNER_FILE_INFO>(_handle);
                Marshal.FreeHGlobal(_handle);
                _handle = IntPtr.Zero;
            }
            if (_filePathPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_filePathPtr);
                _filePathPtr = IntPtr.Zero;
            }
        }
    }
}
