using AzureSignTool.Interop;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace AzureSignTool
{
    public class AuthenticodeSignerCertStoreInfo : IDisposable
    {
        private readonly GCHandle _handle;

        public AuthenticodeSignerCertStoreInfo(MemoryCertificateStore store, X509Certificate2 certificate)
        {
            var storeInfo = new SIGNER_CERT_STORE_INFO(
                dwCertPolicy: SignerCertStoreInfoFlags.SIGNER_CERT_POLICY_CHAIN,
                hCertStore: store.Handle,
                pSigningCert: certificate.Handle
            );
            _handle = GCHandle.Alloc(storeInfo, GCHandleType.Pinned);
        }

        public IntPtr Handle => _handle.AddrOfPinnedObject();


        public void Dispose()
        {
            _handle.Free();
        }
    }
}
