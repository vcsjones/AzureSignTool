namespace AzureSign.Opc
{
    [Flags]
    public enum OpcVerifyOptions
    {
        Default = VerifySignatureValidity | VerifyProviderCertificateMatch,

        /// <summary>
        /// Verify that the package is signed and that all package signatures are valid
        /// </summary>
        VerifySignatureValidity = 0b0001,

        /// <summary>
        /// Verify that all package signatures use the provided certificate
        /// </summary>
        VerifyProviderCertificateMatch = 0b0010,
    }
}
