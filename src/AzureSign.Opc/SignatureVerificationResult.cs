using System.IO.Packaging;
using AzureSign.Opc.Exceptions;

namespace AzureSign.Opc;

public record SignatureVerificationResult(VerificationStatus Status, string Message = "", Exception? Exception = null)
{
    public void ThrowIfFailed()
    {
        if (Status is VerificationStatus.Success)
        {
            return;
        }
        if (Exception is null)
        {
            var details = string.IsNullOrEmpty(Message) ? Status.ToString() : Message;
            throw new VerificationException(Status, $"Signature verification failed: {details}");
        }
        throw Exception;
    }

    public static SignatureVerificationResult Success() => new(VerificationStatus.Success);

    public static SignatureVerificationResult Fail(VerifyResult packageVerifyResult) => new((VerificationStatus)packageVerifyResult);

    public static SignatureVerificationResult Fail(VerificationStatus status, string message = "") => new(status, message);

    public static SignatureVerificationResult Fail(Exception exception) => new(VerificationStatus.Failed, exception.Message, exception);
}
