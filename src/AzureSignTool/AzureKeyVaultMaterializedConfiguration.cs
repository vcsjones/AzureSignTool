using System;
using System.Security.Cryptography.X509Certificates;

using Azure.Core;


namespace AzureSignTool
{
    public sealed record AzureKeyVaultMaterializedConfiguration(TokenCredential TokenCredential, X509Certificate2 PublicCertificate, Uri KeyId);
}
