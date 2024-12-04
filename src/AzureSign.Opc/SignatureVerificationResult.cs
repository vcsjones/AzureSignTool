using AzureSign.Opc.Exceptions;

namespace AzureSign.Opc;

public record SignatureVerificationResult(VerificationStatus Status, string Message = "")
{
    public void ThrowIfFailed()
    {
        if (Status is VerificationStatus.Success)
        {
            return;
        }
        var details = string.IsNullOrEmpty(Message) ? Status.ToString() : Message;
        throw new VerificationException(Status, $"Signature verification failed: {details}");
    }

    public static SignatureVerificationResult Success() => new(VerificationStatus.Success, "");
}
