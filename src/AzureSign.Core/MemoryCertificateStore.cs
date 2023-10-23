using static Windows.Win32.PInvoke;
using Windows.Win32.Security.Cryptography;
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

        public unsafe static MemoryCertificateStore Create()
        {
            const string STORE_TYPE = "Memory";
            var handle = CertOpenStore(STORE_TYPE, 0, (HCRYPTPROV_LEGACY)0, 0, (void*)IntPtr.Zero);
            if (handle == (void*)IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to create a memory certificate store.");
            }
            return new MemoryCertificateStore((IntPtr)(void*)handle);
        }

        public void Close() => Dispose(true);
        void IDisposable.Dispose() => Dispose(true);
        ~MemoryCertificateStore() => Dispose(false);

        public unsafe HCERTSTORE Handle => (HCERTSTORE)(void*)_store.StoreHandle;
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

        private unsafe void FreeHandle()
        {
            if (_handle != IntPtr.Zero)
            {
                var closed = CertCloseStore((HCERTSTORE)(void *)_handle, 0);
                _handle = IntPtr.Zero;
                Debug.Assert(closed);
            }
        }
    }
}
