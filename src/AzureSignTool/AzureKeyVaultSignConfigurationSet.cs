using System;

namespace AzureSignTool
{
    public sealed class AzureKeyVaultSignConfigurationSet
    {
        public bool ManagedIdentity { get; init; }
        public string AzureClientId { get; init; }
        public string AzureClientSecret { get; init; }
        public string AzureTenantId { get; init; }
        public Uri AzureKeyVaultUrl { get; init; }
        public string AzureKeyVaultCertificateName { get; init; }
        public string AzureKeyVaultCertificateVersion { get; init; }
        public string AzureAccessToken { get; init; }
        public string AzureAuthority { get; init; }
    }
}
