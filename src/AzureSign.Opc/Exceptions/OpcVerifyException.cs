namespace AzureSign.Opc.Exceptions;

public class OpcVerifyException(OpcVerifyStatus status, string message, Exception? innerException)
    : Exception(message, innerException)
{
    public OpcVerifyStatus Status { get; init; } = status;

    public OpcVerifyException(OpcVerifyStatus status, string message)
        : this(status, message, null) { }
}
