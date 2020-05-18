using System;
using System.Security.Cryptography.X509Certificates;

using Azure.Core;


namespace AzureSignTool
{
    public class AzureKeyVaultMaterializedConfiguration
    {
        public AzureKeyVaultMaterializedConfiguration(TokenCredential credential, X509Certificate2 publicCertificate, Uri keyId)
        {
            TokenCredential = credential;
            KeyId = keyId;
            PublicCertificate = publicCertificate;
        }

        public X509Certificate2 PublicCertificate { get; }
        public TokenCredential TokenCredential { get; }
        public Uri KeyId { get; }
    }
}
