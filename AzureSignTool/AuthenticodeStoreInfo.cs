using AzureSignTool.Interop;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace AzureSignTool
{
    public sealed class AuthenticodeSignerCertStoreInfo : IDisposable
    {
        private IntPtr _handle;

        public AuthenticodeSignerCertStoreInfo(MemoryCertificateStore store, X509Certificate2 certificate)
        {
            var storeInfo = new SIGNER_CERT_STORE_INFO(
                dwCertPolicy: SignerCertStoreInfoFlags.SIGNER_CERT_POLICY_CHAIN,
                hCertStore: store.Handle,
                pSigningCert: certificate.Handle
            );
            _handle = Marshal2.AllocHGlobal<SIGNER_CERT_STORE_INFO>();
            Marshal.StructureToPtr(storeInfo, _handle, false);
        }

        public IntPtr Handle => _handle;

        public void Dispose() => Dispose(true);
        ~AuthenticodeSignerCertStoreInfo() => Dispose(false);

        private void Dispose(bool disposing)
        {
            if (_handle != IntPtr.Zero)
            {
                Marshal.DestroyStructure<SIGNER_CERT_STORE_INFO>(_handle);
                Marshal.FreeHGlobal(_handle);
            }
            _handle = IntPtr.Zero;
        }
    }
}
