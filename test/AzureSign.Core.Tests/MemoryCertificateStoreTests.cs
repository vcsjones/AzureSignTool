using System;
using System.Security.Cryptography.X509Certificates;
using Xunit;
using AzureSign.Core;

namespace AzureSign.Core.Tests
{
    public class MemoryCertificateStoreTests
    {
        [Fact]
        public void ShouldCreateAndDisposeAMemoryCertificateStore()
        {
            var store = MemoryCertificateStore.Create();
            Assert.NotEqual(default, store.Handle);
            Assert.Empty(store.Certificates);
            store.Close();
        }

        [Fact]
        public void MultipleCloseOrDisposeCallsShouldNotError()
        {
            var store = MemoryCertificateStore.Create();
            store.Close();
            store.Close();
        }

        [Fact]
        public void ShouldAddCertificate()
        {
            using (var store = MemoryCertificateStore.Create())
            {
                using (var cert = new X509Certificate2("testcerts\\kevin_jones.cer"))
                {
                    Assert.Empty(store.Certificates);
                    store.Add(cert);
                    Assert.NotEmpty(store.Certificates);
                }
            }
        }
    }
}
