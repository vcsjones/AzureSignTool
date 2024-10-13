using AzureSign.Core.Interop;
using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace AzureSign.Core
{
    internal sealed class MemoryCertificateStore : IDisposable
    {
        private IntPtr _handle;
        private readonly X509Store _store;

        private MemoryCertificateStore(IntPtr handle)
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

        public static MemoryCertificateStore Create()
        {
            const string STORE_TYPE = "Memory";
            var handle = crypt32.CertOpenStore(STORE_TYPE, CertEncodingType.NONE, IntPtr.Zero, CertOpenStoreFlags.NONE, IntPtr.Zero);
            if (handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to create a memory certificate store.");
            }
            return new MemoryCertificateStore(handle);
        }

        public void Close() => Dispose(true);
        void IDisposable.Dispose() => Dispose(true);
        ~MemoryCertificateStore() => Dispose(false);

        public IntPtr Handle => _store.StoreHandle;
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
            if (_handle != IntPtr.Zero)
            {
                var closed = crypt32.CertCloseStore(_handle, CertCloreStoreFlags.NONE);
                _handle = IntPtr.Zero;
                Debug.Assert(closed);
            }
        }
    }
}
