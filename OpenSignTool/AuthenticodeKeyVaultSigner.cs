using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Crypto = System.Security.Cryptography;

namespace OpenSignTool
{
    public class AuthenticodeKeyVaultSigner : IDisposable
    {
        private readonly AzureKeyVaultMaterializedConfiguration _configuration;
        private readonly MemoryCertificateStore _certificateStore;
        private readonly X509Chain _chain;

        public AuthenticodeKeyVaultSigner(AzureKeyVaultMaterializedConfiguration configuration)
        {
            _configuration = configuration;
            _certificateStore = MemoryCertificateStore.Create();
            _chain = new X509Chain();
            //We don't care about the trustworthiness of the cert. We just want a chain to sign with.
            _chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
            if (!_chain.Build(_configuration.PublicCertificate))
            {
                throw new InvalidOperationException("Failed to build chain for certificate.");
            }
            for(var i = 0; i < _chain.ChainElements.Count; i++)
            {
                _certificateStore.Add(_chain.ChainElements[i].Certificate);
            }
        }

        public async Task SignFile(string path)
        {
            
        }

        public void Dispose()
        {
            _chain.Dispose();
            _certificateStore.Close();
        }
    }

    public sealed class AzureKeyVaultSignConfigurationSet
    {
        public string AzureClientId { get; set; }
        public string AzureClientSecret { get; set; }
        public string AzureKeyVaultUrl { get; set; }
        public string AzureKeyVaultCertificateName { get; set; }
        public string AzureAccessToken { get; set; }

        public Crypto.HashAlgorithmName FileDigestAlgorithm { get; set; }

        public bool Validate()
        {
            // Logging candidate.
            if (string.IsNullOrWhiteSpace(AzureAccessToken))
            {
                if (string.IsNullOrWhiteSpace(AzureClientId))
                {
                    return false;
                }
                if (string.IsNullOrWhiteSpace(AzureClientSecret))
                {
                    return false;
                }
            }

            if (string.IsNullOrWhiteSpace(AzureKeyVaultUrl))
            {
                return false;
            }
            if (string.IsNullOrWhiteSpace(AzureKeyVaultCertificateName))
            {
                return false;
            }
            return true;
        }
    }

    internal static class KeyVaultConfigurationDiscoverer
    {
        public static async Task<AzureKeyVaultMaterializedConfiguration> Materialize(AzureKeyVaultSignConfigurationSet configuration)
        {
            async Task<string> Authenticate(string authority, string resource, string scope)
            {
                if (!string.IsNullOrWhiteSpace(configuration.AzureAccessToken))
                {
                    return configuration.AzureAccessToken;
                }

                var context = new AuthenticationContext(authority);
                ClientCredential credential = new ClientCredential(configuration.AzureClientId, configuration.AzureClientSecret);

                AuthenticationResult result = await context.AcquireTokenAsync(resource, credential);
                if (result == null)
                {
                    throw new InvalidOperationException("Authentication to Azure failed.");
                }
                return result.AccessToken;
            }
            var client = new HttpClient();
            var vault = new KeyVaultClient(Authenticate, client);
            var azureCertificate = await vault.GetCertificateAsync(configuration.AzureKeyVaultUrl, configuration.AzureKeyVaultCertificateName);
            var x509Certificate = new X509Certificate2(azureCertificate.Cer);
            var keyId = azureCertificate.KeyIdentifier;
            var key = await vault.GetKeyAsync(keyId.Identifier);
            return new AzureKeyVaultMaterializedConfiguration(vault, x509Certificate, key, configuration.FileDigestAlgorithm);
        }
    }

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
