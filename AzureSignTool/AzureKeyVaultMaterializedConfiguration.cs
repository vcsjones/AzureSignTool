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
            KeyBundle key, Crypto.HashAlgorithmName fileDigestAlgorithm)
        {
            Client = client;
            Key = key;
            PublicCertificate = publicCertificate;
            FileDigestAlgorithm = fileDigestAlgorithm;
        }

        public Crypto.HashAlgorithmName FileDigestAlgorithm { get; }

        public X509Certificate2 PublicCertificate { get; }
        public KeyVaultClient Client { get; }
        public KeyBundle Key { get; }

        public void Dispose()
        {
            Client.Dispose();
        }
    }
}
