using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using System;
using System.Security.Cryptography.X509Certificates;
using Crypto = System.Security.Cryptography;

namespace AzureSignTool
{
    public class AzureKeyVaultMaterializedConfiguration : IDisposable
    {
        public AzureKeyVaultMaterializedConfiguration(KeyVaultClient client, X509Certificate2 publicCertificate,
            string keyId, Crypto.HashAlgorithmName fileDigestAlgorithm)
        {
            Client = client;
            KeyId = keyId;
            PublicCertificate = publicCertificate;
            FileDigestAlgorithm = fileDigestAlgorithm;
        }

        public Crypto.HashAlgorithmName FileDigestAlgorithm { get; }

        public X509Certificate2 PublicCertificate { get; }
        public KeyVaultClient Client { get; }
        public string KeyId { get; }

        public void Dispose()
        {
            Client.Dispose();
        }
    }
}
