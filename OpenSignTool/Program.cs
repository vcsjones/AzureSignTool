using Microsoft.Extensions.CommandLineUtils;
using System.Security.Cryptography;

namespace OpenSignTool
{
    class Program
    {
        static int Main(string[] args)
        {
            var application = new CommandLineApplication(throwOnUnexpectedArg: false);
            var signCommand = application.Command("sign", throwOnUnexpectedArg: false, configuration: cfg =>
            {
                cfg.Description = "Signs a file.";
                var fileDigestAlgorithm = cfg.Option("-fd | --file-digest", "The digest algorithm to hash the file with.", CommandOptionType.SingleValue);

                var azureKeyVaultUrl = cfg.Option("-kvu | --azure-key-vault-url", "The URL to an Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultClientId = cfg.Option("-kvi | --azure-key-vault-client-id", "The Client ID to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultClientSecret = cfg.Option("-kvs | --azure-key-vault-client-secret", "The Client Secret to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultCertificateName = cfg.Option("-kvc | --azure-key-vault-certificate", "The name of the certificate in Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultAccessToken = cfg.Option("-kva | --azure-key-vault-accesstoken", "The Access Token to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
                var file = cfg.Argument("file", "The path to the file.");
                cfg.HelpOption("-? | -h | --help");

                cfg.OnExecute(async () =>
                {
                    var configuration = new AzureKeyVaultSignConfigurationSet
                    {
                        AzureKeyVaultUrl = azureKeyVaultUrl.Value(),
                        AzureKeyVaultCertificateName = azureKeyVaultCertificateName.Value(),
                        AzureClientId = azureKeyVaultClientId.Value(),
                        AzureAccessToken = azureKeyVaultAccessToken.Value(),
                        AzureClientSecret = azureKeyVaultClientSecret.Value(),
                        FileDigestAlgorithm = AlgorithmFromInput(fileDigestAlgorithm.Value()).GetValueOrDefault(HashAlgorithmName.SHA256)
                    };

                    using (var materialized = await KeyVaultConfigurationDiscoverer.Materialize(configuration))
                    using (var signer = new AuthenticodeKeyVaultSigner(materialized))
                    {
                        return signer.SignFile(file.Value);
                    }
                });
            });
            return application.Execute(args);
        }


        private static HashAlgorithmName? AlgorithmFromInput(string value)
        {
            switch (value?.ToLower())
            {
                case "sha1":
                    return HashAlgorithmName.SHA1;
                case "sha384":
                    return HashAlgorithmName.SHA384;
                case "sha512":
                    return HashAlgorithmName.SHA512;
                case null:
                case "sha256":
                    return HashAlgorithmName.SHA256;
                default:
                    return null;

            }
        }
    }
}
