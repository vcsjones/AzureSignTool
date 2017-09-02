using Microsoft.Extensions.CommandLineUtils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace AzureSignTool
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
                var description = cfg.Option("-d | --description", "Provide a description of the signed content.", CommandOptionType.SingleValue);
                var descriptionUrl = cfg.Option("-du | --description-url", "Provide a URL with more information about the signed content.", CommandOptionType.SingleValue);
                var rfc3161TimeStamp = cfg.Option("-tr | --timestamp-rfc3161", "Specifies the RFC 3161 timestamp server's URL. If this option (or -t) is not specified, the signed file will not be timestamped.", CommandOptionType.SingleValue);
                var rfc3161Digest = cfg.Option("-td | --timestamp-digest", "Used with the -tr switch to request a digest algorithm used by the RFC 3161 timestamp server.", CommandOptionType.SingleValue);
                var acTimeStamp = cfg.Option("-t | --timestamp-authenticode", "Specify the timestamp server's URL. If this option is not present, the signed file will not be timestamped.", CommandOptionType.SingleValue);

                var file = cfg.Argument("file", "The path to the file.");
                cfg.HelpOption("-? | -h | --help");

                cfg.OnExecute(async () =>
                {
                    if (!CheckMutuallyExclusive(acTimeStamp, rfc3161TimeStamp) |
                        ! CheckRequired(azureKeyVaultUrl, azureKeyVaultCertificateName))
                    {
                        return 1;
                    }
                    if (!azureKeyVaultAccessToken.HasValue() && !CheckRequired(azureKeyVaultClientId, azureKeyVaultClientSecret))
                    {
                        return 1;
                    }
                    if (string.IsNullOrWhiteSpace(file.Value))
                    {
                        Console.WriteLine("File is required.");
                        return 1;
                    }
                    var configuration = new AzureKeyVaultSignConfigurationSet
                    {
                        AzureKeyVaultUrl = azureKeyVaultUrl.Value(),
                        AzureKeyVaultCertificateName = azureKeyVaultCertificateName.Value(),
                        AzureClientId = azureKeyVaultClientId.Value(),
                        AzureAccessToken = azureKeyVaultAccessToken.Value(),
                        AzureClientSecret = azureKeyVaultClientSecret.Value(),
                        FileDigestAlgorithm = AlgorithmFromInput(fileDigestAlgorithm.Value()).GetValueOrDefault(HashAlgorithmName.SHA256)
                    };

                    var timestampConfiguration = new TimeStampConfiguration
                    {
                        Url = rfc3161TimeStamp.HasValue() ? rfc3161TimeStamp.Value() :
                              acTimeStamp.HasValue() ? acTimeStamp.Value() : null,
                        Type = rfc3161TimeStamp.HasValue() ? TimeStampType.RFC3161 :
                              acTimeStamp.HasValue() ? TimeStampType.Authenticode : TimeStampType.None,
                        DigestAlgorithm = rfc3161Digest.HasValue() ?
                            AlgorithmFromInput(rfc3161Digest.Value()).GetValueOrDefault(HashAlgorithmName.SHA256) :
                            HashAlgorithmName.SHA256
                    };

                    using (var materialized = await KeyVaultConfigurationDiscoverer.Materialize(configuration))
                    using (var signer = new AuthenticodeKeyVaultSigner(materialized, timestampConfiguration))
                    {
                        var result = signer.SignFile(file.Value, description.Value(), descriptionUrl.Value());
                        Console.WriteLine($"Signing completed as {result}.");
                        return result;
                    }
                });
            });
            if (args.Length == 0)
            {
                application.ShowHelp();
            }
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

        private static bool CheckMutuallyExclusive(params CommandOption[] commands)
        {
            if (commands.Length < 2)
            {
                return true;
            }
            var set = new HashSet<string>(commands.Where(c => c.HasValue()).Select(c => $"-{c.ShortName}"));
            if (set.Count > 1)
            {
                Console.WriteLine($"Cannot use {String.Join(", ", set)} options together.");
                return false;
            }
            return true;
        }

        private static bool CheckRequired(params CommandOption[] commands)
        {
            var set = new HashSet<string>(commands.Where(c => !c.HasValue()).Select(c => $"-{c.ShortName}"));
            if (set.Count > 0)
            {
                Console.WriteLine($"Options {String.Join(", ", set)} are required.");
                return false;
            }
            return true;
        }
    }
}
