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
            var details = string.IsNullOrEmpty(Message) ? Status.ToString() : Message;
            throw new OpcVerifyException(Status, $"OPC verify failed: {details}");
        }
        throw Exception;
    }

    public static OpcVerifyResult Success() => new(OpcVerifyStatus.Success);

    public static OpcVerifyResult Fail(VerifyResult packageVerifyResult) =>
        new((OpcVerifyStatus)packageVerifyResult);

    public static OpcVerifyResult Fail(OpcVerifyStatus status, string message = "") =>
        new(status, message);

    public static OpcVerifyResult Fail(Exception exception) =>
        new(OpcVerifyStatus.Failed, exception.Message, exception);
}
