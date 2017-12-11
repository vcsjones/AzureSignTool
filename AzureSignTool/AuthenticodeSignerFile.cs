using AzureSignTool.Interop;
using System;
using System.Runtime.InteropServices;
using System.Threading;

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
            GC.SuppressFinalize(this);
            var cleanupHandle = Interlocked.Exchange(ref _handle, IntPtr.Zero);
            if (cleanupHandle != IntPtr.Zero)
            {
                Marshal.DestroyStructure<SIGNER_FILE_INFO>(cleanupHandle);
                Marshal.FreeHGlobal(cleanupHandle);
            }
            var cleanupFilePathPtr = Interlocked.Exchange(ref _filePathPtr, IntPtr.Zero);
            if (cleanupFilePathPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(cleanupFilePathPtr);
                cleanupFilePathPtr = IntPtr.Zero;
            }
        }
    }
}
