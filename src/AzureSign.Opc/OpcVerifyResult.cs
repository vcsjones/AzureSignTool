using System.IO;
using System.IO.Packaging;
using AzureSign.Opc.Exceptions;

namespace AzureSign.Opc;

public record OpcVerifyResult(
    OpcVerifyStatus Status,
    string Message = "",
    Exception? Exception = null
)
{
    public void ThrowIfFailed()
    {
        if (Status is OpcVerifyStatus.Success)
        {
            return;
        }
        if (Exception is null)
        {
            var message = string.IsNullOrEmpty(Message) ? $"OPC verify failed: {Status}." : Message;
            throw new OpcVerifyException(Status, message);
        }
        throw Exception;
    }

    public static OpcVerifyResult Success() => new(OpcVerifyStatus.Success);

    public static OpcVerifyResult Fail(VerifyResult packageVerifyResult) =>
        new((OpcVerifyStatus)packageVerifyResult);

    public static OpcVerifyResult Fail(OpcVerifyStatus status, string message = "") =>
        new(status, message);

    public static OpcVerifyResult Fail(OpcVerifyStatus status, Exception exception) =>
        new(status, exception.Message, exception);

    public static OpcVerifyResult Fail(Exception exception)
    {
        var status = exception switch
        {
            IOException => OpcVerifyStatus.IoError,
            InvalidDataException => OpcVerifyStatus.InvalidData,

            _ => OpcVerifyStatus.Failed,
        };
        return new(status, exception.Message, exception);
    }
}
