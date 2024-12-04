using System.Security.Cryptography;

namespace AzureSign.Opc;

public interface IOpcSigner
{
    Task<byte[]> Sign(string packagePath, CancellationToken ct = default);

    Task<SignatureVerificationResult> VerifySignatures(
        string packagePath,
        VerificationOptions options = VerificationOptions.Default,
        CancellationToken ct = default
    );
}
