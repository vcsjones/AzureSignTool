namespace AzureSign.Opc.Exceptions;

public class VerificationException(
    VerificationStatus status,
    string message,
    Exception? innerException
) : Exception(message, innerException)
{
    public VerificationStatus Status { get; init; } = status;

    public VerificationException(VerificationStatus status, string message)
        : this(status, message, null) { }
}
