namespace AzureSign.Opc;

public interface IOpcSigner
{
    Task<byte[]> Sign(string packagePath, CancellationToken ct = default);

    Task<OpcVerifyResult> Verify(
        string packagePath,
        OpcVerifyOptions options = OpcVerifyOptions.Default,
        CancellationToken ct = default
    );
}
