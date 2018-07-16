using Microsoft.Azure.KeyVault;
using System.Security.Cryptography.X509Certificates;

namespace AzureSignTool
{
    public class AzureKeyVaultMaterializedConfiguration
    {
        public AzureKeyVaultMaterializedConfiguration(KeyVaultClient client, X509Certificate2 publicCertificate, KeyIdentifier keyId)
        {
            Client = client;
            KeyId = keyId;
            PublicCertificate = publicCertificate;
        }

        public X509Certificate2 PublicCertificate { get; }
        public KeyVaultClient Client { get; }
        public KeyIdentifier KeyId { get; }
    }
}
