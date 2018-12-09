using AzureSign.Core;
using McMaster.Extensions.CommandLineUtils;
using McMaster.Extensions.CommandLineUtils.Abstractions;
using McMaster.Extensions.CommandLineUtils.Conventions;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

using static AzureSignTool.HRESULT;

namespace AzureSignTool
{
    internal sealed class SignCommand
    {
        [Option("-kvu | --azure-key-vault-url", "The URL to an Azure Key Vault.", CommandOptionType.SingleValue), UriValidator, Required]
        public string KeyVaultUri { get; set; }

        [Option("-kvi | --azure-key-vault-client-id", "The Client ID to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue)]
        public (bool Present, string Value) KeyVaultClientId { get; set; }

        [Option("-kvs | --azure-key-vault-client-secret", "The Client Secret to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue)]
        public (bool Present, string Value) KeyVaultClientSecret { get; set; }

        [Option("-kvc | --azure-key-vault-certificate", "The name of the certificate in Azure Key Vault.", CommandOptionType.SingleValue), Required]
        public string KeyVaultCertificate { get; set; }

        [Option("-kva | --azure-key-vault-accesstoken", "The Access Token to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue)]
        public (bool Present, string Value) KeyVaultAccessToken { get; set; }

        [Option("-d | --description", "Provide a description of the signed content.", CommandOptionType.SingleValue)]
        public string Description { get; set; }

        [Option("-du | --description-url", "Provide a URL with more information about the signed content.", CommandOptionType.SingleValue), UriValidator]
        public string DescriptionUri { get; set; }

        [Option("-tr | --timestamp-rfc3161", "Specifies the RFC 3161 timestamp server's URL. If this option (or -t) is not specified, the signed file will not be timestamped.", CommandOptionType.SingleValue), UriValidator]
        public (bool Present, string Uri) Rfc3161Timestamp { get; set; }

        [Option("-td | --timestamp-digest", "Used with the -tr switch to request a digest algorithm used by the RFC 3161 timestamp server.", CommandOptionType.SingleValue)]
        [AllowedValues("sha1", "sha256", "sha384", "sha512", IgnoreCase = true)]
        public HashAlgorithmName TimestampDigestAlgorithm { get; set; } = HashAlgorithmName.SHA256;

        [Option("-fd | --file-digest", "The digest algorithm to hash the file with.", CommandOptionType.SingleValue)]
        [AllowedValues("sha1", "sha256", "sha384", "sha512", IgnoreCase = true)]
        public HashAlgorithmName FileDigestAlgorithm { get; set; } = HashAlgorithmName.SHA256;

        [Option("-t | --timestamp-authenticode", "Specify the timestamp server's URL. If this option is not present, the signed file will not be timestamped.", CommandOptionType.SingleValue), UriValidator]
        public (bool Present, string Uri) AuthenticodeTimestamp { get; set; }

        [Option("-ac | --additional-certificates", "Specify one or more certificates to include in the public certificate chain.", CommandOptionType.MultipleValue), FileExists]
        public string[] AdditionalCertificates { get; set; } = Array.Empty<string>();

        [Option("-v | --verbose", "Include additional output.", CommandOptionType.NoValue)]
        public bool Verbose { get; set; }

        [Option("-q | --quiet", "Do not print any output to the console.", CommandOptionType.NoValue)]
        public bool Quiet { get; set; }

        [Option("-ph | --page-hashing", "Generate page hashes for executable files if supported.", CommandOptionType.NoValue)]
        public bool PageHashing { get; set; }

        [Option("-nph | --no-page-hashing", "Suppress page hashes for executable files if supported.", CommandOptionType.NoValue)]
        public bool NoPageHashing { get; set; }

        [Option("-coe | --continue-on-error", "Continue signing multiple files if an error occurs.", CommandOptionType.NoValue)]
        public bool ContinueOnError { get; set; }

        [Option("-ifl | --input-file-list", "A path to a file that contains a list of files, one per line, to sign.", CommandOptionType.SingleValue), FileExists]
        public string InputFileList { get; set; }

        [Option("-mdop | --max-degree-of-parallelism", "The maximum number of concurrent signing operations.", CommandOptionType.SingleValue), Range(-1, int.MaxValue)]
        public int? MaxDegreeOfParallelism { get; set; }

        // We manually validate the file's existance with the --input-file-list. Don't validate here.
        [Argument(0, "file", "The path to the file.")]
        public string[] Files { get; set; } = Array.Empty<string>();

        private HashSet<string> _allFiles;
        public HashSet<string> AllFiles
        {
            get
            {
                if (_allFiles == null)
                {
                    _allFiles = new HashSet<string>(Files);
                    if (!string.IsNullOrWhiteSpace(InputFileList))
                    {
                        _allFiles.UnionWith(File.ReadAllLines(InputFileList).Where(s => !string.IsNullOrWhiteSpace(s)));
                    }
                }
                return _allFiles;
            }
        }

        private ValidationResult OnValidate(ValidationContext context, CommandLineContext appContext)
        {
            if (PageHashing && NoPageHashing)
            {
                return new ValidationResult("Cannot use '--page-hashing' and '--no-page-hashing' options together.", new[] { nameof(NoPageHashing), nameof(PageHashing) });
            }
            if (Quiet && Verbose)
            {
                return new ValidationResult("Cannot use '--quiet' and '--verbose' options together.", new[] { nameof(NoPageHashing), nameof(PageHashing) });
            }
            if (!OneTrue(KeyVaultAccessToken.Present, KeyVaultClientId.Present))
            {
                return new ValidationResult("One of '--key-vault-access-token' or '--key-vault-client-id' must be supplied.", new[] { nameof(KeyVaultAccessToken), nameof(KeyVaultClientId) });
            }

            if (Rfc3161Timestamp.Present && AuthenticodeTimestamp.Present)
            {
                return new ValidationResult("Cannot use '--timestamp-rfc3161' and '--timestamp-authenticode' options together.", new[] { nameof(Rfc3161Timestamp), nameof(AuthenticodeTimestamp) });
            }

            if (KeyVaultClientId.Present && !KeyVaultClientSecret.Present)
            {
                return new ValidationResult("Must supply '--key-vault-client-secret' when using '--key-vault-client-id'.", new[] { nameof(KeyVaultClientSecret) });
            }
            if (AllFiles.Count == 0)
            {
                return new ValidationResult("At least one file must be specified to sign.");
            }
            foreach(var file in AllFiles)
            {
                if (!File.Exists(file))
                {
                    return new ValidationResult($"File '{file}' does not exist.");
                }
            }
            return ValidationResult.Success;
        }

        public int OnValidationError(ValidationResult result, CommandLineApplication<SignCommand> command, IConsole console)
        {
            console.ForegroundColor = ConsoleColor.Red;
            console.Error.WriteLine(result.ErrorMessage);
            console.ResetColor();
            command.ShowHint();
            return E_INVALIDARG;
        }

        public async Task<int> OnExecuteAsync(CommandLineApplication app, IConsole console)
        {
            LogLevel level;
            if (Quiet)
            {
                level = LogLevel.Critical;
            }
            else if (Verbose)
            {
                level = LogLevel.Trace;
            }
            else
            {
                level = LogLevel.Information;
            }

            var loggerFactory = new LoggerFactory();
            loggerFactory.AddConsole(level, true);
            var logger = loggerFactory.CreateLogger<SignCommand>();
            X509Certificate2Collection certificates;

            switch (GetAdditionalCertificates(AdditionalCertificates, logger))
            {
                case ErrorOr<X509Certificate2Collection>.Ok d:
                    certificates = d.Value;
                    break;
                case ErrorOr<X509Certificate2Collection>.Err err:
                    logger.LogError(err.Error, err.Error.Message);
                    return E_INVALIDARG;
                default:
                    logger.LogError("Failed to include additional certificates.");
                    return E_INVALIDARG;
            }

            var configuration = new AzureKeyVaultSignConfigurationSet
            {
                AzureKeyVaultUrl = KeyVaultUri,
                AzureKeyVaultCertificateName = KeyVaultCertificate,
                AzureClientId = KeyVaultClientId.Value,
                AzureAccessToken = KeyVaultAccessToken.Value,
                AzureClientSecret = KeyVaultClientSecret.Value,
            };

            TimeStampConfiguration timeStampConfiguration;

            if (Rfc3161Timestamp.Present)
            {
                timeStampConfiguration = new TimeStampConfiguration(Rfc3161Timestamp.Uri, TimestampDigestAlgorithm, TimeStampType.RFC3161);
            }
            else if (AuthenticodeTimestamp.Present)
            {
                timeStampConfiguration = new TimeStampConfiguration(AuthenticodeTimestamp.Uri, default, TimeStampType.Authenticode);
            }
            else
            {
                timeStampConfiguration = TimeStampConfiguration.None;
            }
            bool? performPageHashing = null;
            if (PageHashing)
            {
                performPageHashing = true;
            }
            if (NoPageHashing)
            {
                performPageHashing = false;
            }
            var configurationDiscoverer = new KeyVaultConfigurationDiscoverer(logger);
            var materializedResult = await configurationDiscoverer.Materialize(configuration);
            AzureKeyVaultMaterializedConfiguration materialized;
            switch (materializedResult)
            {
                case ErrorOr<AzureKeyVaultMaterializedConfiguration>.Ok ok:
                    materialized = ok.Value;
                    break;
                default:
                    logger.LogInformation("Failed to get configuration from Azure Key Vault.");
                    return E_INVALIDARG;
            }
            int failed = 0, succeeded = 0;
            var cancellationSource = new CancellationTokenSource();
            console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cancellationSource.Cancel();
                logger.LogInformation("Cancelling signing operations.");
            };
            var options = new ParallelOptions();
            if (MaxDegreeOfParallelism.HasValue)
            {
                options.MaxDegreeOfParallelism = MaxDegreeOfParallelism.Value;
            }
            logger.LogTrace("Creating context");
            var context = new KeyVaultContext(materialized.Client, materialized.KeyId, materialized.PublicCertificate);
            using (var keyVault = new RSAKeyVault(context))
            using (var signer = new AuthenticodeKeyVaultSigner(keyVault, materialized.PublicCertificate, FileDigestAlgorithm, timeStampConfiguration, certificates))
            {
                Parallel.ForEach(AllFiles, options, () => (succeeded: 0, failed: 0), (filePath, pls, state) =>
                {
                    if (cancellationSource.IsCancellationRequested)
                    {
                        pls.Stop();
                    }
                    if (pls.IsStopped)
                    {
                        return state;
                    }
                    using (var loopScope = logger.BeginScope("File: {Id}", filePath))
                    {
                        logger.LogInformation($"Signing file {filePath}");
                        var result = signer.SignFile(filePath, Description, DescriptionUri, performPageHashing, logger);
                        switch (result)
                        {
                            case COR_E_BADIMAGEFORMAT:
                                logger.LogError($"The Publisher Identity in the AppxManifest.xml does not match the subject on the certificate for file {filePath}.");
                                break;
                        }

                        if (result == S_OK)
                        {
                            logger.LogInformation($"Signing completed successfully for file {filePath}.");
                            return (state.succeeded + 1, state.failed);
                        }
                        else
                        {
                            logger.LogError($"Signing failed with error {result:X2} for file {filePath}.");
                            if (!ContinueOnError || AllFiles.Count == 1)
                            {
                                logger.LogInformation("Stopping file signing.");
                                pls.Stop();
                            }

                            return (state.succeeded, state.failed + 1);
                        }
                    }
                }, result =>
                {
                    Interlocked.Add(ref failed, result.failed);
                    Interlocked.Add(ref succeeded, result.succeeded);
                });
            }
            logger.LogInformation($"Successful operations: {succeeded}");
            logger.LogInformation($"Failed operations: {failed}");
            if (failed > 0 && succeeded == 0)
            {
                return E_ALL_FAILED;
            }
            else if (failed > 0)
            {
                return S_SOME_SUCCESS;
            }
            else
            {
                return S_OK;
            }
        }


        private static ErrorOr<X509Certificate2Collection> GetAdditionalCertificates(IEnumerable<string> paths, ILogger logger)
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
                            logger.LogTrace($"Including additional certificate {certificate.Thumbprint}.");
                            collection.Add(certificate);
                            break;
                        default:
                            return new Exception($"Specified file {path} is not a public valid certificate.");
                    }
                }
            }
            catch (CryptographicException e)
            {
                logger.LogError($"An exception occured while including an additional certificate:\n{e}");
                return e;
            }

            return collection;
        }

        private static bool OneTrue(bool left, bool right) => left != right && (left || right);
    }
}
