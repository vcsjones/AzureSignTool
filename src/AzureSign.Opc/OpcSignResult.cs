using System.IO;
using AzureSign.Opc.Exceptions;

namespace AzureSign.Opc;

public record OpcSignResult(
    OpcSignStatus Status,
    string Message = "",
    Exception? Exception = default,
    byte[]? PackageSignature = default
)
{
    public bool IsSuccess() => Status == OpcSignStatus.Success;

    public void ThrowIfFailed()
    {
        if (IsSuccess())
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

    public static OpcSignResult Fail(Exception exception)
    {
        var status = exception switch
        {
            IOException => OpcSignStatus.IoError,
            InvalidDataException => OpcSignStatus.InvalidData,

            _ => OpcSignStatus.Failed,
        };
        return new(status, exception.Message, exception);
    }
}
