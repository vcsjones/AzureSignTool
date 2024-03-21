namespace ReSignMsixBundle.BusinessLogic;

/// <summary>The AzureSignTool argument builder. This class cannot be inherited.</summary>
[SupportedOSPlatform("windows")] internal sealed class AzureSignToolArgumentBuilder
{
    private readonly List<string> _args = ["sign"];

    public AzureSignToolArgumentBuilder(ReSignCommand reSignCommand)
    {
        CreateCommonArgs(reSignCommand);
    }

    public override string ToString()
    {
        return string.Join(" ", _args.Select(s => s.Contains(' ') ? $"\"{s}\"" : s));
    }

    /// <summary>Return the arguments, with the specified extra arguments.</summary>
    /// <param name="extraArgs">The extra arguments.</param>
    /// <returns>A string[].</returns>
    public string[] WithExtraArguments(IEnumerable<string> extraArgs)
    {
        return _args.Union(extraArgs).ToArray();
    }

    /// <summary>Return the arguments, with the specified extra arguments.</summary>
    /// <param name="extraArgs">The extra arguments.</param>
    /// <returns>A string[].</returns>
    public string[] WithExtraArguments(params string[] extraArgs)
    {
        return _args.Union(extraArgs).ToArray();
    }

    private void CreateCommonArgs(ReSignCommand reSignCommand)
    {
        if (!string.IsNullOrEmpty(reSignCommand.KeyVaultUri))
        {
            _args.Add("-kvu");
            _args.Add(reSignCommand.KeyVaultUri);
        }

        if (reSignCommand.KeyVaultClientId.Present && !string.IsNullOrEmpty(reSignCommand.KeyVaultClientId.Value))
        {
            _args.Add("-kvi");
            _args.Add(reSignCommand.KeyVaultClientId.Value);
        }

        if (reSignCommand.KeyVaultClientSecret.Present && !string.IsNullOrEmpty(reSignCommand.KeyVaultClientSecret.Value))
        {
            _args.Add("-kvs");
            _args.Add(reSignCommand.KeyVaultClientSecret.Value);
        }

        if (reSignCommand.KeyVaultTenantId.Present && !string.IsNullOrEmpty(reSignCommand.KeyVaultTenantId.Value))
        {
            _args.Add("-kvt");
            _args.Add(reSignCommand.KeyVaultTenantId.Value);
        }

        if (!string.IsNullOrEmpty(reSignCommand.KeyVaultCertificate))
        {
            _args.Add("-kvc");
            _args.Add(reSignCommand.KeyVaultCertificate);
        }

        if (reSignCommand.KeyVaultAccessToken.Present && !string.IsNullOrEmpty(reSignCommand.KeyVaultAccessToken.Value))
        {
            _args.Add("-kva");
            _args.Add(reSignCommand.KeyVaultAccessToken.Value);
        }

        if (reSignCommand.UseManagedIdentity)
        {
            _args.Add("-kvm");
        }

        if (reSignCommand.Rfc3161Timestamp.Present && !string.IsNullOrEmpty(reSignCommand.Rfc3161Timestamp.Uri))
        {
            _args.Add("-tr");
            _args.Add(reSignCommand.Rfc3161Timestamp.Uri);
            // TODO Temporarily disabled because command line parsing fails if this option is included
            //_args.Add("-td");
            //_args.Add(reSignCommand.TimestampDigestAlgorithm.ToString());
        }

        _args.Add("-fd");
        _args.Add(reSignCommand.FileDigestAlgorithm.ToString());

        if (reSignCommand.Verbose)
        {
            _args.Add("-v");
        }

        if (reSignCommand.Quiet)
        {
            _args.Add("-q");
        }

        if (reSignCommand.ContinueOnError)
        {
            _args.Add("-coe");
        }

        if (reSignCommand.MaxDegreeOfParallelism.HasValue)
        {
            _args.Add("-mdop");
            _args.Add(reSignCommand.MaxDegreeOfParallelism.Value.ToString());
        }

        if (reSignCommand.Colors)
        {
            _args.Add("--colors");
        }
    }
}
