using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
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
                    LoggerServiceLocator.Current.Log("Acquiring access token from client id", LogLevel.Verbose);
                    var result = await context.AcquireTokenAsync(resource, credential);
                    LoggerServiceLocator.Current.Log("Acquired access token from client id", LogLevel.Verbose);
                    return result.AccessToken;
                }
                catch (AdalServiceException e) when (e.StatusCode >= 400 && e.StatusCode < 500)
                {
                    authenticationFailure = true;
                    LoggerServiceLocator.Current.Log("Failed to authenticate to Azure Key Vault. Please check credentials.");
                    return null;
                }
            }

            var vault = new KeyVaultClient(Authenticate);
            
            X509Certificate2 certificate;
            CertificateBundle azureCertificate;
            try
            {
                LoggerServiceLocator.Current.Log($"Retrieving certificate {configuration.AzureKeyVaultCertificateName}.", LogLevel.Verbose);
                azureCertificate = await vault.GetCertificateAsync(configuration.AzureKeyVaultUrl, configuration.AzureKeyVaultCertificateName);
                LoggerServiceLocator.Current.Log($"Retrieved certificate {configuration.AzureKeyVaultCertificateName}.", LogLevel.Verbose);
                
                certificate = new X509Certificate2(azureCertificate.Cer);
            }
            catch (Exception e)
            {
                if (!authenticationFailure)
                {
                    LoggerServiceLocator.Current.Log($"Failed to retrieve certificate {configuration.AzureKeyVaultCertificateName} from Azure Key Vault. Please verify the name of the certificate and the permissions to the certificate.");
                }
                return e;
            }
            var keyId = azureCertificate.KeyIdentifier;
            return new AzureKeyVaultMaterializedConfiguration(vault, certificate, keyId.Identifier, configuration.FileDigestAlgorithm);

        }
    }
}
