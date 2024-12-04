namespace AzureSign.Opc;

public interface IOpcSigner
{
    Task<OpcSignResult> Sign(string packagePath, CancellationToken ct = default);

    Task<OpcVerifyResult> Verify(
        string packagePath,
        OpcVerifyOptions options = OpcVerifyOptions.Default,
        CancellationToken ct = default
    );
}
