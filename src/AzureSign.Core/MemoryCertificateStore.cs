using static Windows.Win32.PInvoke;
using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

using Windows.Win32.Security.Cryptography;

// CsWin32 marks the crypt32 store APIs as Windows-only. This library is Windows-only by design,
// so the platform compatibility analyzer's reachability warnings do not apply here.
#pragma warning disable CA1416

namespace AzureSign.Core
{
    internal sealed class MemoryCertificateStore : IDisposable
    {
        private HCERTSTORE _handle;
        private readonly X509Store _store;

        private MemoryCertificateStore(HCERTSTORE handle)
        {
            _handle = handle;
            try
            {
                _store = new X509Store(_handle);
            }
            catch
            {
                //We need to manually clean up the handle here. If we throw here for whatever reason,
                //we'll leak the handle because we'll have a partially constructed object that won't get
                //a finalizer called on or anything to dispose of.
                FreeHandle();
                throw;
            }
        }

        public unsafe static MemoryCertificateStore Create()
        {
            const string STORE_TYPE = "Memory";
            var handle = CertOpenStore(STORE_TYPE, 0, 0, null);
            if (handle.IsNull)
            {
                throw new InvalidOperationException("Failed to create a memory certificate store.");
            }
            return new MemoryCertificateStore(handle);
        }

        public void Close() => Dispose(true);
        void IDisposable.Dispose() => Dispose(true);
        ~MemoryCertificateStore() => Dispose(false);

        public HCERTSTORE Handle => (HCERTSTORE)_store.StoreHandle;
        public void Add(X509Certificate2 certificate) => _store.Add(certificate);
        public void Add(X509Certificate2Collection collection) => _store.AddRange(collection);
        public X509Certificate2Collection Certificates => _store.Certificates;

        private void Dispose(bool disposing)
        {
            GC.SuppressFinalize(this);

            if (disposing)
            {
                _store.Dispose();
            }

            FreeHandle();
        }

        private void FreeHandle()
        {
            if (!_handle.IsNull)
            {
                var closed = CertCloseStore(_handle, 0);
                _handle = HCERTSTORE.Null;
                Debug.Assert(closed);
            }
        }
    }
}
