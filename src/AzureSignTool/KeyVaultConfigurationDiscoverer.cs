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
                if (string.IsNullOrWhiteSpace(configuration.AzureAuthority))
                {
                    credential = new ClientSecretCredential(configuration.AzureTenantId, configuration.AzureClientId, configuration.AzureClientSecret);
                }
                else
                {
                    ClientSecretCredentialOptions options = new()
                    {
                        AuthorityHost = AuthorityHostNames.GetUriForAzureAuthorityIdentifier(configuration.AzureAuthority)
                    };
                    credential = new ClientSecretCredential(configuration.AzureTenantId, configuration.AzureClientId, configuration.AzureClientSecret, options);
                }
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
            catch (Exception e)
            {
                _logger.LogError($"Failed to retrieve certificate {configuration.AzureKeyVaultCertificateName} from Azure Key Vault. Please verify the name of the certificate and the permissions to the certificate. Error message: {e.Message}.");
                _logger.LogTrace(e.ToString());

                return e;
            }
            var keyId = azureCertificate.KeyId;

            if (keyId is null)
            {
                return new InvalidOperationException("The Azure certificate does not have an associated private key.");
            }

            return new AzureKeyVaultMaterializedConfiguration(credential, certificate, keyId);
        }
    }
}
