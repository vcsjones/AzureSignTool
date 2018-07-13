using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Extensions.Logging;
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
                    LoggerServiceLocator.Current.LogTrace("Acquiring access token from client id");
                    var result = await context.AcquireTokenAsync(resource, credential);
                    LoggerServiceLocator.Current.LogTrace("Acquired access token from client id");
                    return result.AccessToken;
                }
                catch (AdalServiceException e) when (e.StatusCode >= 400 && e.StatusCode < 500)
                {
                    authenticationFailure = true;
                    LoggerServiceLocator.Current.LogError("Failed to authenticate to Azure Key Vault. Please check credentials.");
                    return null;
                }
            }

            var vault = new KeyVaultClient(Authenticate);
            
            X509Certificate2 certificate;
            CertificateBundle azureCertificate;
            try
            {
                LoggerServiceLocator.Current.LogTrace($"Retrieving certificate {configuration.AzureKeyVaultCertificateName}.");
                azureCertificate = await vault.GetCertificateAsync(configuration.AzureKeyVaultUrl, configuration.AzureKeyVaultCertificateName);
                LoggerServiceLocator.Current.LogTrace($"Retrieved certificate {configuration.AzureKeyVaultCertificateName}.");
                
                certificate = new X509Certificate2(azureCertificate.Cer);
            }
            catch (Exception e)
            {
                if (!authenticationFailure)
                {
                    LoggerServiceLocator.Current.LogError($"Failed to retrieve certificate {configuration.AzureKeyVaultCertificateName} from Azure Key Vault. Please verify the name of the certificate and the permissions to the certificate.");
                }
                return e;
            }
            var keyId = azureCertificate.KeyIdentifier;
            return new AzureKeyVaultMaterializedConfiguration(vault, certificate, keyId.Identifier, configuration.FileDigestAlgorithm);

        }
    }
}
