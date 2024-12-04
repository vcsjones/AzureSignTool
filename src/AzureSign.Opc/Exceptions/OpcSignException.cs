namespace AzureSign.Opc.Exceptions;

public class OpcSignException(OpcSignStatus status, string message, Exception? innerException)
    : Exception(message, innerException)
{
    public OpcSignStatus Status { get; init; } = status;

    public OpcSignException(OpcSignStatus status, string message)
        : this(status, message, null) { }
}
