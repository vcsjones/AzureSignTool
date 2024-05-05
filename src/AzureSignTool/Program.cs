#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using XenoAtom.CommandLine;

namespace AzureSignTool
{
    public class Program
    {
        public static Task<int> Main(string[] args)
        {
            // if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            // {
            //     Console.Error.WriteLine("Azure Sign Tool is only supported on Windows.");
            //     return E_PLATFORMNOTSUPPORTED;
            // }

            var app = new CommandApp("azuresigntool")
            {
                new VersionOption(prototype: "version"),
                new HelpOption(),
                new SignCommand(),
            };

            return app.RunAsync(args).AsTask();
        }
    }

    internal sealed class SignCommand : Command
    {
        internal string? KeyVaultUrl { get; set; }
        internal string? KeyVaultClientId { get; set; }
        internal string? KeyVaultClientSecret { get; set; }
        internal string? KeyVaultTenantId { get; set; }
        internal string? KeyVaultCertificate { get; set; }
        internal string? KeyVaultAccessToken { get; set; }
        internal bool UseManagedIdentity { get; set; }
        internal string? SignDescription { get; set; }
        internal string? SignDescriptionUrl { get; set; }
        internal string? Rfc3161Timestamp { get; set; }
        internal string? TimestampDigestAlgorithm { get; set; }
        internal string? FileDigestAlgorithm { get; set; }
        internal string? AuthenticodeTimestampUrl { get; set; }
        internal List<string> AdditionalCertificates { get; } = [];
        internal bool Verbose { get; set; }
        internal bool Quiet { get; set; }
        internal bool PageHashing { get; set; }
        internal bool NoPageHashing { get; set; }
        internal bool ContinueOnError { get; set; }
        internal string? InputFileList { get; set; }
        internal int? MaxDegreeOfParallelism { get; set; }
        internal bool Colors { get; set; }
        internal bool SkipSignedFiles { get; set; }
        internal bool AppendSignature { get; set; }
        internal string? AzureAuthority { get; set; }

        public SignCommand() : base("sign", "Sign a file.", null)
        {
            this.Add(new HelpOption());
            this.Add("kvu|azure-key-vault-url=", "The {URL} to an Azure Key Vault.", v => KeyVaultUrl = v);
            this.Add("kvi|azure-key-vault-client-id=", "The Client {ID} to authenticate to the Azure Key Vault.", v => KeyVaultClientId = v);
            this.Add("kvs|azure-key-vault-client-secret=", "The Client Secret to authenticate to the Azure Key Vault.", v => KeyVaultClientSecret = v);
            this.Add("kvt|azure-key-vault-tenant-id=", "The Tenant Id to authenticate to the Azure Key Vault.", v => KeyVaultTenantId = v);
            this.Add("kvc|azure-key-vault-certificate=", "The name of the certificate in Azure Key Vault.", v => KeyVaultCertificate = v);
            this.Add("kva|azure-key-vault-accesstoken=", "The Access Token to authenticate to the Azure Key Vault.", v => KeyVaultAccessToken = v);
            this.Add("kvm|azure-key-vault-managed-identity", "Use the current Azure mananaged identity.", v => UseManagedIdentity = v is not null);
            this.Add("d|description=", "Provide a description of the signed content.", v => SignDescription = v);
            this.Add("du|description-url=", "Provide a URL with more information about the signed content.", v => SignDescriptionUrl = v);
            this.Add("tr|timestamp-rfc3161=", "Specifies the RFC 3161 timestamp server's URL. If this option (or -t) is not specified, the signed file will not be timestamped.", v => Rfc3161Timestamp = v);
            this.Add("td|timestamp-digest=", "Used with the -tr switch to request a digest algorithm used by the RFC 3161 timestamp server.", v => TimestampDigestAlgorithm = v);
            this.Add("fd|file-digest=", "The digest algorithm to hash the file with.", v => FileDigestAlgorithm = v);
            this.Add("t|timestamp-authenticode=", "Specify the legacy timestamp server's URL. This option is generally not recommended. Use the --timestamp-rfc3161 option instead.", v => AuthenticodeTimestampUrl = v);
            this.Add("ac|additional-certificates=", "Specify one or more certificates to include in the public certificate chain.", AdditionalCertificates);
            this.Add("v|verbose", "Specify one or more certificates to include in the public certificate chain.", v => Verbose = v is not null);
            this.Add("q|quiet", "Do not print any output to the console.", v => Quiet = v is not null);
            this.Add("ph|page-hashing", "Generate page hashes for executable files if supported.", v => PageHashing = v is not null);
            this.Add("nph|no-page-hashing", "Suppress page hashes for executable files if supported.", v => NoPageHashing = v is not null);
            this.Add("coe|continue-on-error", "Continue signing multiple files if an error occurs.", v => ContinueOnError = v is not null);
            this.Add("ifl|input-file-list=", "A path to a file that contains a list of files, one per line, to sign.", v => InputFileList = v);
            this.Add("mdop|max-degree-of-parallelism=", "The maximum number of concurrent signing operations.", (int v) => MaxDegreeOfParallelism = v);
            this.Add("colors", "Enable color output on the command line.", v => Colors = v is not null);
            this.Add("s|skip-signed", "Skip files that are already signed.", v => SkipSignedFiles = v is not null);
            this.Add("as|append-signature", "Append the signature, has no effect with --skip-signed.", v => AppendSignature = v is not null);
            this.Add("au|azure-authority=", "The Azure Authority for Azure Key Vault.", v => AzureAuthority = v);
            Action = Run;
        }

        private ValueTask<int> Run(CommandRunContext context, string[] arguments)
        {
            Console.WriteLine(MaxDegreeOfParallelism);
            return ValueTask.FromResult(0);
        }
    }
}
