namespace AzureSign.Opc;

public enum OpcSignStatus
{
    /// <summary>
    /// The package was signed successfully.
    /// </summary>
    Success,

    /// <summary>
    /// The package was not signed successfully.
    /// </summary>
    Failed,

    /// <summary>
    /// The input file cannot be read from or written to.
    /// </summary>
    IoError,

    /// <summary>
    /// The input package is invalid.
    /// </summary>
    InvalidData,

    /// <summary>
    /// There is an issue with the provided certificate or crypto algorithm.
    /// </summary>
    CertificateError,
}
