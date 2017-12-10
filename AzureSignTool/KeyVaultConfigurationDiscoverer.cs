using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace AzureSignTool
{
    internal static class KeyVaultConfigurationDiscoverer
    {
        public static async Task<ErrorOr<AzureKeyVaultMaterializedConfiguration>> Materialize(AzureKeyVaultSignConfigurationSet configuration)
        {
            var authenticationFailure = false;
            async Task<string> Authenticate(string authority, string resource, string scope)
            {
                if (!string.IsNullOrWhiteSpace(configuration.AzureAccessToken))
                {
                    return configuration.AzureAccessToken;
                }

                var context = new AuthenticationContext(authority);
                ClientCredential credential = new ClientCredential(configuration.AzureClientId, configuration.AzureClientSecret);

                try
                {
                    var result = await context.AcquireTokenAsync(resource, credential);
                    return result.AccessToken;
                }
                catch (AdalServiceException e) when (e.StatusCode >= 400 && e.StatusCode < 500)
                {
                    authenticationFailure = true;
                    await LoggerServiceLocator.Current.Log("Failed to authenticate to Azure Key Vault. Please check credentials.");
                    return null;
                }
            }
            var client = new HttpClient();
            var vault = new KeyVaultClient(Authenticate, client);
            
            X509Certificate2 certificate;
            CertificateBundle azureCertificate;
            try
            {
                await LoggerServiceLocator.Current.Log($"Retrieving certificate {configuration.AzureKeyVaultCertificateName}.", LogLevel.Verbose);
                azureCertificate = await vault.GetCertificateAsync(configuration.AzureKeyVaultUrl, configuration.AzureKeyVaultCertificateName);
                await LoggerServiceLocator.Current.Log($"Retrieved certificate {configuration.AzureKeyVaultCertificateName}.", LogLevel.Verbose);
                certificate = new X509Certificate2(azureCertificate.Cer);
            }
            catch (Exception e)
            {
                if (!authenticationFailure)
                {
                    await LoggerServiceLocator.Current.Log($"Failed to retrieve certificate {configuration.AzureKeyVaultCertificateName} from Azure Key Vault. Please verify the name of the certificate and the permissions to the certificate.");
                }
                return e;
            }
            var keyId = azureCertificate.KeyIdentifier;
            KeyBundle key;
            try
            {
                await LoggerServiceLocator.Current.Log($"Retrieving key {keyId.Identifier}.", LogLevel.Verbose);
                key = await vault.GetKeyAsync(keyId.Identifier);
                await LoggerServiceLocator.Current.Log($"Retrieved key {keyId.Identifier}.", LogLevel.Verbose);
            }
            catch (Exception e)
            {
                if (!authenticationFailure)
                {
                    await LoggerServiceLocator.Current.Log($"Failed to retrieve key {keyId.Identifier} from Azure Key Vault. Please verify the name of the certificate and the permissions to the certificate.");
                }
                return e;
            }
            return new AzureKeyVaultMaterializedConfiguration(vault, certificate, key, configuration.FileDigestAlgorithm);

        }
    }
}
