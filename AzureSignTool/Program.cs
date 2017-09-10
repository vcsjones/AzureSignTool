using Microsoft.Extensions.CommandLineUtils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using static AzureSignTool.HRESULT;

namespace AzureSignTool
{
    class Program
    {
        static int Main(string[] args)
        {
            LoggerServiceLocator.Current = new ConsoleLogger();
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
                var additionalCertificates = cfg.Option("-ac | --additional-certificates", "Specify one or more certificates to include in the public certificate chain.", CommandOptionType.MultipleValue);
                var verbose = cfg.Option("-v | --verbose", "Include additional output.", CommandOptionType.NoValue);
                var quiet = cfg.Option("-q | --quiet", "Do not print any output to the console.", CommandOptionType.NoValue);
                var pageHashing = cfg.Option("-ph | --page-hashing", "Generate page hashes for executable files if supported.", CommandOptionType.NoValue);
                var noPageHashing = cfg.Option("-nph | --no-page-hashing", "Suppress page hashes for executable files if supported.", CommandOptionType.NoValue);

                var file = cfg.Argument("file", "The path to the file.");
                cfg.HelpOption("-? | -h | --help");

                cfg.OnExecute(async () =>
                {
                    X509Certificate2Collection certificates;
                    switch (await GetAdditionalCertificates(additionalCertificates.Values))
                    {
                        case ErrorOr<X509Certificate2Collection>.Ok d:
                            certificates = d.Value;
                            break;
                        case ErrorOr<X509Certificate2Collection>.Err err:
                            await LoggerServiceLocator.Current.Log(err.Error.Message);
                            return E_INVALIDARG;
                        default:
                            await LoggerServiceLocator.Current.Log("Failed to include additional certificates.");
                            return E_INVALIDARG;
                    }

                    if (!await CheckMutuallyExclusive(quiet, verbose))
                    {
                        return E_INVALIDARG;
                    }

                    if (quiet.HasValue())
                    {
                        LoggerServiceLocator.Current.Level = LogLevel.Quiet;
                    }
                    else if (verbose.HasValue())
                    {
                        LoggerServiceLocator.Current.Level = LogLevel.Verbose;
                    }

                    if (!await CheckMutuallyExclusive(acTimeStamp, rfc3161TimeStamp) |
                        !await CheckRequired(azureKeyVaultUrl, azureKeyVaultCertificateName) |
                        !await CheckMutuallyExclusive(pageHashing, noPageHashing))
                    {
                        return E_INVALIDARG;
                    }
                    if (!azureKeyVaultAccessToken.HasValue() && !await CheckRequired(azureKeyVaultClientId, azureKeyVaultClientSecret))
                    {
                        return E_INVALIDARG;
                    }
                    if (string.IsNullOrWhiteSpace(file.Value))
                    {
                        await LoggerServiceLocator.Current.Log("File is required.");
                        return E_INVALIDARG;
                    }
                    if (!File.Exists(file.Value))
                    {
                        await LoggerServiceLocator.Current.Log("File does not exist.");
                        return E_FILE_NOT_FOUND;
                    }
                    var configuration = new AzureKeyVaultSignConfigurationSet
                    {
                        AzureKeyVaultUrl = azureKeyVaultUrl.Value(),
                        AzureKeyVaultCertificateName = azureKeyVaultCertificateName.Value(),
                        AzureClientId = azureKeyVaultClientId.Value(),
                        AzureAccessToken = azureKeyVaultAccessToken.Value(),
                        AzureClientSecret = azureKeyVaultClientSecret.Value(),
                        FileDigestAlgorithm = GetValueFromOption(fileDigestAlgorithm, AlgorithmFromInput, HashAlgorithmName.SHA256)
                    };

                    var timestampConfiguration = new TimeStampConfiguration
                    {
                        Url = rfc3161TimeStamp.HasValue() ? rfc3161TimeStamp.Value() :
                              acTimeStamp.HasValue() ? acTimeStamp.Value() : null,
                        Type = rfc3161TimeStamp.HasValue() ? TimeStampType.RFC3161 :
                              acTimeStamp.HasValue() ? TimeStampType.Authenticode : TimeStampType.None,
                        DigestAlgorithm = GetValueFromOption(rfc3161Digest, AlgorithmFromInput, HashAlgorithmName.SHA256)
                    };

                    bool? performPageHashing = null;
                    if (pageHashing.HasValue())
                    {
                        performPageHashing = true;
                    }
                    if (noPageHashing.HasValue())
                    {
                        performPageHashing = false;
                    }

                    using (var materialized = await KeyVaultConfigurationDiscoverer.Materialize(configuration))
                    {
                        if (materialized == null)
                        {
                            await LoggerServiceLocator.Current.Log($"Failed to get configuration from Azure Key Vault.");
                            return E_INVALIDARG;
                        }
                        using (var signer = new AuthenticodeKeyVaultSigner(materialized, timestampConfiguration, certificates))
                        {
                            var result = signer.SignFile(file.Value, description.Value(), descriptionUrl.Value(), performPageHashing);
                            switch (result)
                            {
                                case COR_E_BADIMAGEFORMAT:
                                    await LoggerServiceLocator.Current.Log("The Publisher Identity in the AppxManifest.xml does not match the subject on the certificate.");
                                    break;
                            }
                            if (result == S_OK)
                            {
                                await LoggerServiceLocator.Current.Log("Signing completed successfully.");
                            }
                            else
                            {
                                await LoggerServiceLocator.Current.Log($"Signing failed with error {result:X2}.");
                            }
                            return result;
                        }
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

        private static async Task<ErrorOr<X509Certificate2Collection>> GetAdditionalCertificates(IEnumerable<string> paths)
        {
            var collection = new X509Certificate2Collection();
            try
            {
                foreach (var path in paths)
                {

                    var type = X509Certificate2.GetCertContentType(path);
                    switch (type)
                    {
                        case X509ContentType.Cert:
                        case X509ContentType.Authenticode:
                        case X509ContentType.SerializedCert:
                            var certificate = new X509Certificate2(path);
                            await LoggerServiceLocator.Current.Log($"Including additional certificate {certificate.Thumbprint}.", LogLevel.Verbose);
                            collection.Add(certificate);
                            break;
                        default:
                            return new Exception($"Specified file {path} is not a public valid certificate.");
                    }
                }
            }
            catch (CryptographicException e)
            {
                await LoggerServiceLocator.Current.Log($"An exception occured while including an additional certificate:\n{e}", LogLevel.Verbose);
                return e;
            }

            return collection;
        }

        private static async Task<bool> CheckMutuallyExclusive(params CommandOption[] commands)
        {
            if (commands.Length < 2)
            {
                return true;
            }
            var set = new HashSet<string>(commands.Where(c => c.HasValue()).Select(c => $"-{c.ShortName}"));
            if (set.Count > 1)
            {
                await LoggerServiceLocator.Current.Log($"Cannot use {String.Join(", ", set)} options together.");
                return false;
            }
            return true;
        }

        private static async Task<bool> CheckRequired(params CommandOption[] commands)
        {
            var set = new HashSet<string>(commands.Where(c => !c.HasValue()).Select(c => $"-{c.ShortName}"));
            if (set.Count > 0)
            {
                await LoggerServiceLocator.Current.Log($"Options {String.Join(", ", set)} are required.");
                return false;
            }
            return true;
        }

        private static T GetValueFromOption<T>(CommandOption option, Func<string, T> transform, T defaultIfNull) where T : class
        {
            if (!option.HasValue())
            {
                return defaultIfNull;
            }
            return transform(option.Value()) ?? defaultIfNull;
        }

        private static T GetValueFromOption<T>(CommandOption option, Func<string, T?> transform, T defaultIfNull) where T : struct
        {
            if (!option.HasValue())
            {
                return defaultIfNull;
            }
            return transform(option.Value()) ?? defaultIfNull;
        }
    }
}
