using System.IO.Packaging;

namespace AzureSign.Opc;

public enum OpcVerifyStatus
{
    /// <summary>
    /// The verification was successful.
    /// </summary>
    Success = VerifyResult.Success,

    /// <summary>
    /// The signature is not valid.
    /// </summary>
    InvalidSignature = VerifyResult.InvalidSignature,

    /// <summary>
    /// The X.509 certificate is not available to verify the signature.
    /// </summary>
    CertificateRequired = VerifyResult.CertificateRequired,

    /// <summary>
    /// The X.509 certificate is not valid.
    /// </summary>
    InvalidCertificate = VerifyResult.InvalidCertificate,

    /// <summary>
    /// A reference relationship to the signature was not found.
    /// </summary>
    ReferenceNotFound = VerifyResult.ReferenceNotFound,

    /// <summary>
    /// The specified package or part has no signature.
    /// </summary>
    NotSigned = VerifyResult.NotSigned,

    /// <summary>
    /// The verification failed.
    /// </summary>
    Failed = 0x1001,

    /// <summary>
    /// The input file cannot be read from.
    /// </summary>
    IoError = 0x1002,

    /// <summary>
    /// The input package is invalid.
    /// </summary>
    InvalidData = 0x1003,

    /// <summary>
    /// A package part with a signature that does not match the provided certificate was found.
    /// </summary>
    UnmatchedPackagePart = 0x1004,
}
