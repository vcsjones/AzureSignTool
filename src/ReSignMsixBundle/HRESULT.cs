using System.Diagnostics.CodeAnalysis;

#pragma warning disable IDE0079
#pragma warning disable IDE1006

namespace ReSignMsixBundle;

[SuppressMessage("ReSharper", "InconsistentNaming"), SuppressMessage("ReSharper", "IdentifierTypo"),
 SuppressMessage("ReSharper", "UnusedMember.Global")]  
internal static class HRESULT
{
    public const int S_OK = 0;
    public const int E_INVALIDARG = unchecked((int)0x80070057);
    public const int COR_E_BADIMAGEFORMAT = unchecked((int)0x8007000B);
    public const int E_FILE_NOT_FOUND = unchecked((int)0x80070002);
    public const int E_PLATFORMNOTSUPPORTED = unchecked((int)0x80131539);

    public const int S_SOME_SUCCESS = 0x20000001;
    public const int E_ALL_FAILED = unchecked((int)0xA0000002);

    public const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
}
