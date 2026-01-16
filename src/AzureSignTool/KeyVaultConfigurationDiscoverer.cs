using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;

using Microsoft.Extensions.Logging;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
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

        public async Task<ErrorOr<AzureKeyVaultMaterializedConfiguration>> Materialize(AzureKeyVaultSignConfigurationSet configuration, int timeoutSeconds)
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
            KeyVaultCertificate azureCertificate;
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds)))
            {
                try
                {
                    var certClient = new CertificateClient(configuration.AzureKeyVaultUrl, credential);

                    if (!string.IsNullOrWhiteSpace(configuration.AzureKeyVaultCertificateVersion))
                    {
                        _logger.LogTrace($"Retrieving version [{configuration.AzureKeyVaultCertificateVersion}] of certificate {configuration.AzureKeyVaultCertificateName}.");
                        azureCertificate = (await certClient.GetCertificateVersionAsync(configuration.AzureKeyVaultCertificateName, configuration.AzureKeyVaultCertificateVersion, cts.Token).ConfigureAwait(false)).Value;
                    }
                    else
                    {
                        _logger.LogTrace($"Retrieving current version of certificate {configuration.AzureKeyVaultCertificateName}.");
                        azureCertificate = (await certClient.GetCertificateAsync(configuration.AzureKeyVaultCertificateName, cts.Token).ConfigureAwait(false)).Value;
                    }
                    _logger.LogTrace($"Retrieved certificate with Id {azureCertificate.Id}.");

                    certificate = X509CertificateLoader.LoadCertificate(azureCertificate.Cer);
                }
                catch (OperationCanceledException)
                {
                    _logger.LogError($"Timeout connecting to Azure Key Vault at {configuration.AzureKeyVaultUrl}. The operation exceeded {timeoutSeconds} seconds.");
                    return new TimeoutException($"The connection to Azure Key Vault timed out after {timeoutSeconds} seconds.");
                }
                catch (Exception e)
                {
                    _logger.LogError($"Failed to retrieve certificate {configuration.AzureKeyVaultCertificateName} from Azure Key Vault. Please verify the name of the certificate and the permissions to the certificate. Error message: {e.Message}.");
                    _logger.LogTrace(e.ToString());

                    return e;
                }
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
