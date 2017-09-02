
using Crypto = System.Security.Cryptography;

namespace AzureSignTool
{
    public sealed class AzureKeyVaultSignConfigurationSet
    {
        public string AzureClientId { get; set; }
        public string AzureClientSecret { get; set; }
        public string AzureKeyVaultUrl { get; set; }
        public string AzureKeyVaultCertificateName { get; set; }
        public string AzureAccessToken { get; set; }

        public Crypto.HashAlgorithmName FileDigestAlgorithm { get; set; }
        public Crypto.HashAlgorithmName PkcsDigestAlgorithm { get; set; }

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
}
