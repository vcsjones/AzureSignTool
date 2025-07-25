using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace AzureSign.Core.Opc.Signatures;

/// <summary>
/// Interface for HLKX package signing operations.
/// </summary>
public interface IHlkxSigner
{
    /// <summary>
    /// Signs an HLKX file using the provided certificate and signing algorithm.
    /// </summary>
    /// <param name="filePath">Path to the HLKX file to sign</param>
    /// <param name="signingAlgorithm">The asymmetric algorithm for signing (typically RSA from Azure Key Vault)</param>
    /// <param name="certificate">The X.509 certificate (public key only)</param>
    /// <param name="hashAlgorithm">The hash algorithm to use for signing</param>
    /// <param name="logger">Optional logger for diagnostic information</param>
    /// <returns>HRESULT indicating success (0) or failure</returns>
    Task<int> SignFileAsync(
        string filePath,
        AsymmetricAlgorithm signingAlgorithm,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        ILogger? logger = null);

    /// <summary>
    /// Verifies the signature of an HLKX file.
    /// </summary>
    /// <param name="filePath">Path to the HLKX file to verify</param>
    /// <param name="logger">Optional logger for diagnostic information</param>
    /// <returns>True if the signature is valid, false otherwise</returns>
    Task<bool> VerifyFileAsync(string filePath, ILogger? logger = null);
}