using AzureSign.Opc.Exceptions;

namespace AzureSign.Opc;

public record OpcSignResult(
    OpcSignStatus Status,
    string Message = "",
    Exception? Exception = default,
    byte[]? PackageSignature = default
)
{
    public void ThrowIfFailed()
    {
        if (Status is OpcSignStatus.Success)
        {
            return;
        }
        if (Exception is null)
        {
            var message = string.IsNullOrEmpty(Message) ? $"OPC sign failed: {Status}." : Message;
            throw new OpcSignException(Status, message);
        }
        throw Exception;
    }

    public static OpcSignResult Success(byte[] packageSignature) =>
        new(OpcSignStatus.Success, PackageSignature: packageSignature);

    public static OpcSignResult Fail(OpcSignStatus status, string message = "") =>
        new(status, message);

    public static OpcSignResult Fail(OpcSignStatus status, Exception exception) =>
        new(status, exception.Message, exception);

    public static OpcSignResult Fail(Exception exception) =>
        new(OpcSignStatus.Failed, exception.Message, exception);
}
