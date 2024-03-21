using JetBrains.Annotations;
using Microsoft.Extensions.Logging.Console;
using ReSignMsixBundle.BusinessLogic;
using ReSignMsixBundle.CommandLineHelpers;

#pragma warning disable IDE0051

namespace ReSignMsixBundle;

[SupportedOSPlatform("windows"), NoReorder]
internal sealed class ReSignCommand
{
    [Option("-kvu | --azure-key-vault-url", "The URL to an Azure Key Vault.", CommandOptionType.SingleValue), UriValidator, Required]
    public string KeyVaultUri { get; set; } = string.Empty;

    [Option("-kvi | --azure-key-vault-client-id", "The Client ID to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue)]
    public (bool Present, string Value) KeyVaultClientId { get; set; }

    [Option("-kvs | --azure-key-vault-client-secret", "The Client Secret to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue)]
    public (bool Present, string Value) KeyVaultClientSecret { get; set; }

    [Option("-kvt | --azure-key-vault-tenant-id", "The Tenant Id to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue)]
    public (bool Present, string Value) KeyVaultTenantId { get; set; }

    [Option("-kvc | --azure-key-vault-certificate", "The name of the certificate in Azure Key Vault.", CommandOptionType.SingleValue), Required]
    public string KeyVaultCertificate { get; set; } = string.Empty;

    [Option("-kva | --azure-key-vault-accesstoken", "The Access Token to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue)]
    public (bool Present, string Value) KeyVaultAccessToken { get; set; }

    [Option("-kvm | --azure-key-vault-managed-identity", CommandOptionType.NoValue)]
    public bool UseManagedIdentity { get; set; }

    [Option("-tr | --timestamp-rfc3161",
         "Specifies the RFC 3161 timestamp server's URL. If this option is not specified, the signed file will not be timestamped.",
         CommandOptionType.SingleValue), UriValidator]
    public (bool Present, string Uri) Rfc3161Timestamp { get; set; }

    [Option("-td | --timestamp-digest",
         "Used with the -tr switch to request a digest algorithm used by the RFC 3161 timestamp server.",
         CommandOptionType.SingleValue), McMaster.Extensions.CommandLineUtils.AllowedValues("sha1", "sha256", "sha384", "sha512", IgnoreCase = true)]
    public HashAlgorithmName TimestampDigestAlgorithm { get; set; } = HashAlgorithmName.SHA256;

    [Option("-fd | --file-digest", "The digest algorithm to hash the file with.", CommandOptionType.SingleValue),
     McMaster.Extensions.CommandLineUtils.AllowedValues("sha1", "sha256", "sha384", "sha512", IgnoreCase = true)]
    public HashAlgorithmName FileDigestAlgorithm { get; set; } = HashAlgorithmName.SHA256;

    [Option("-v | --verbose", "Include additional output.", CommandOptionType.NoValue)]
    public bool Verbose { get; set; }

    [Option("-q | --quiet", "Do not print any output to the console.", CommandOptionType.NoValue)]
    public bool Quiet { get; set; }

    [Option("-coe | --continue-on-error", "Continue signing multiple files if an error occurs.", CommandOptionType.NoValue)]
    public bool ContinueOnError { get; set; }

    [Option("-mdop | --max-degree-of-parallelism", "The maximum number of concurrent signing operations.", CommandOptionType.SingleValue),
     Range(-1, int.MaxValue)]
    public int? MaxDegreeOfParallelism { get; set; }

    [Option("--colors", "Enable color output on the command line.", CommandOptionType.NoValue)]
    public bool Colors { get; set; } = false;

    [Option("-pnf | --publisher-name-file",
         "The path to the file that contains the publisher name. (This text is in a file to avoid issues with quotes.)",
         CommandOptionType.SingleValue), Required]
    public string PublisherNameFile { get; set; } = string.Empty;

    [Argument(0, "bundle-file", "The path to the bundle file.")]
    public string BundleFile { get; set; } = String.Empty;

    public LogLevel LogLevel => Quiet ? LogLevel.Critical : Verbose ? LogLevel.Trace : LogLevel.Information;

    [UsedImplicitly]
    public async Task<int> OnExecuteAsync(IConsole console)
    {
        using var loggerFactory = LoggerFactory.Create(ConfigureLogging);
        var logger = loggerFactory.CreateLogger<ReSignCommand>();

        var cancellationTokenSource = new CancellationTokenSource();
        console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
#pragma warning disable AsyncFixer02
            cancellationTokenSource.Cancel();
#pragma warning restore AsyncFixer02
            logger.LogInformation("Cancelling signing operations");
        };
        var cancellationToken = cancellationTokenSource.Token;

        logger.LogInformation("Extract bundle {BundleFile}", BundleFile);
        using var zipHelper = new ZipHelper(logger);

        var msixFiles = zipHelper.ExtractZipFile(BundleFile, cancellationToken);
        if (cancellationToken.IsCancellationRequested || msixFiles.Count == 0)
        {
            return HRESULT.E_ALL_FAILED;
        }

        var publisherName = (await File.ReadAllTextAsync(PublisherNameFile, cancellationToken).ConfigureAwait(false)).Trim();

        logger.LogInformation("Manifests in the MSIX files are modified to reflect publisher: {PublisherName}", publisherName);
        new PackagePublisherTool(logger).ModifyPackagePublisher(msixFiles, publisherName, cancellationToken);
        if (cancellationToken.IsCancellationRequested)
        {
            return HRESULT.E_ALL_FAILED;
        }

        var args = new AzureSignToolArgumentBuilder(this);

        logger.LogInformation("Signing the individual MSIX files; options: {Options}", args);
        var result = AzureSignTool.Program.Main(args.WithExtraArguments(msixFiles));
        if (result != HRESULT.S_OK)
        {
            logger.LogCritical("Could not sign the MSIX files");
            return HRESULT.E_ALL_FAILED;
        }

        var makeAppxPath = X64ExePathFinder.Find("makeappx.exe", logger);
        if (cancellationToken.IsCancellationRequested || string.IsNullOrEmpty(makeAppxPath))
        {
            return HRESULT.E_ALL_FAILED;
        }

        using var processAsyncHelper = new ProcessAsyncHelper();

        var arguments = $"""
                         bundle /p "{BundleFile}" /d "{zipHelper.TempDirectory}" /o
                         """;
        logger.LogInformation("Creating new MSIX bundle: \"{MakeAppxPath}\" {Arguments}", makeAppxPath, arguments);
        var processResult =
            await processAsyncHelper.ExecuteShellCommandAsync(makeAppxPath, arguments, (int)TimeSpan.FromMinutes(5).TotalMilliseconds);
        if (processResult.ExitCode == 0)
        {
            logger.LogInformation("MakeAppx output: {Output}", processResult.Output);
        }
        else
        {
            logger.LogCritical("MakeAppx failed: {Output}", processResult.Output);
            return HRESULT.E_ALL_FAILED;
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return HRESULT.E_ALL_FAILED;
        }

        logger.LogInformation("Signing the MSIX bundle file; options: {Options}", args);
        result = AzureSignTool.Program.Main(args.WithExtraArguments(BundleFile));
        if (result == HRESULT.S_OK)
        {
            logger.LogInformation("All steps completed successfully");
        }

        return result;
    }

    [UsedImplicitly]
    public static int OnValidationError(ValidationResult result, CommandLineApplication<ReSignCommand> command, IConsole console)
    {
        console.ForegroundColor = ConsoleColor.Red;
        console.Error.WriteLine(result.ErrorMessage);
        console.ResetColor();
        command.ShowHint();
        return HRESULT.E_INVALIDARG;
    }

    private void ConfigureLogging(ILoggingBuilder builder)
    {
        builder.AddSimpleConsole(console =>
        {
            console.IncludeScopes = true;
            console.ColorBehavior = Colors ? LoggerColorBehavior.Enabled : LoggerColorBehavior.Disabled;
        });

        builder.SetMinimumLevel(LogLevel);
    }

    private static bool OneTrue(params bool[] values)
    {
        return values.Count(v => v) == 1;
    }

    [UsedImplicitly]
    private ValidationResult OnValidate()
    {
        if (Quiet && Verbose)
        {
            return new ValidationResult("Cannot use '--quiet' and '--verbose' options together.", new[] { nameof(Quiet), nameof(Verbose) });
        }

        if (!OneTrue(KeyVaultAccessToken.Present, KeyVaultClientId.Present, UseManagedIdentity))
        {
            return new ValidationResult(
                "One of '--azure-key-vault-accesstoken', '--azure-key-vault-client-id' or '--azure-key-vault-managed-identity' must be supplied.",
                new[] { nameof(KeyVaultAccessToken), nameof(KeyVaultClientId) });
        }

        switch (KeyVaultClientId.Present)
        {
            case true when !KeyVaultClientSecret.Present:
                return new ValidationResult("Must supply '--azure-key-vault-client-secret' when using '--azure-key-vault-client-id'.",
                    new[] { nameof(KeyVaultClientSecret) });
            case true when !KeyVaultTenantId.Present:
                return new ValidationResult("Must supply '--azure-key-vault-tenant-id' when using '--azure-key-vault-client-id'.",
                    new[] { nameof(KeyVaultTenantId) });
        }

        if (UseManagedIdentity && (KeyVaultAccessToken.Present || KeyVaultClientId.Present))
        {
            return new ValidationResult(
                "Cannot use '--azure-key-vault-managed-identity' and '--azure-key-vault-accesstoken' or '--azure-key-vault-client-id'",
                new[] { nameof(UseManagedIdentity) });
        }

        if (!File.Exists(PublisherNameFile))
        {
            return new ValidationResult($"File '{PublisherNameFile}' does not exist.");
        }

        if (string.IsNullOrEmpty(BundleFile))
        {
            return new ValidationResult("Cannot omit the path to the MSIX bundle file.");
        }

        return File.Exists(BundleFile) ? ValidationResult.Success! : new ValidationResult($"File '{BundleFile}' does not exist.");
    }
}
