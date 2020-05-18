using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;

using Microsoft.Extensions.Logging;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace AzureSignTool
{
    internal class KeyVaultConfigurationDiscoverer
    {
        private readonly ILogger _logger;

        public KeyVaultConfigurationDiscoverer(ILogger logger)
        {
            _logger = logger;
        }

        public async Task<ErrorOr<AzureKeyVaultMaterializedConfiguration>> Materialize(AzureKeyVaultSignConfigurationSet configuration)
        {
            TokenCredential credential;
            if (configuration.ManagedIdentity)
            {
                credential = new DefaultAzureCredential();
            }
            else if(!string.IsNullOrWhiteSpace(configuration.AzureAccessToken))
            {
                credential = new AccessTokenCredential(configuration.AzureAccessToken);
            }
            else
            {
                credential = new ClientSecretCredential(configuration.AzureTenantId, configuration.AzureClientId, configuration.AzureClientSecret);
            }


            X509Certificate2 certificate;
            KeyVaultCertificateWithPolicy azureCertificate;
            try
            {
                var certClient = new CertificateClient(configuration.AzureKeyVaultUrl, credential);

                _logger.LogTrace($"Retrieving certificate {configuration.AzureKeyVaultCertificateName}.");
                azureCertificate = (await certClient.GetCertificateAsync(configuration.AzureKeyVaultCertificateName).ConfigureAwait(false)).Value;
                _logger.LogTrace($"Retrieved certificate {configuration.AzureKeyVaultCertificateName}.");
                
                certificate = new X509Certificate2(azureCertificate.Cer);
            }
            catch (KeyVaultErrorException kvException)
            {
                if (authenticationFailure)
                {
                    return kvException;
                }

                _logger.LogError($"Failed to retrieve certificate {configuration.AzureKeyVaultCertificateName} from Azure Key Vault. Please verify the name of the certificate and the permissions to the certificate.");

                var error = kvException.Body.Error;
                _logger.LogError($"KeyVault Error Code: {error.Code}, Message: {error.Message}");

                if (error.InnerError != null)
                {
                    _logger.LogError($"KeyVault Inner Error Code: {error.InnerError.Code}, Message: {error.InnerError.Message}");
                }

                return kvException;
            }
            catch (Exception e)
            {
                if (!authenticationFailure)
                {
                    _logger.LogError($"Failed to retrieve certificate {configuration.AzureKeyVaultCertificateName} from Azure Key Vault. Please verify the name of the certificate and the permissions to the certificate. Message: '{e.Message}'");
                }
                return e;
            }
            var keyId = azureCertificate.KeyId;
            return new AzureKeyVaultMaterializedConfiguration(credential, certificate, keyId);
        }
    }
}
