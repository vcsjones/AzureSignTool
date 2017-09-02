using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace AzureSignTool
{
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
}
