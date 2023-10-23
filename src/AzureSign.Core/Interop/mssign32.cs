using System;
using System.Runtime.InteropServices;
using Windows.Win32.Security.Cryptography;

namespace AzureSign.Core.Interop
{
 
    [type: StructLayout(LayoutKind.Sequential)]
    internal unsafe struct SIGNER_SIGN_EX3_PARAMS
    {
        public SIGNER_SIGN_FLAGS dwFlags;
        public SIGNER_SUBJECT_INFO* pSubjectInfo;
        public SIGNER_CERT* pSignerCert;
        public SIGNER_SIGNATURE_INFO* pSignatureInfo;
        public IntPtr pProviderInfo;
        public SIGNER_TIMESTAMP_FLAGS dwTimestampFlags;
        public string? pszTimestampAlgorithmOid;
        public char* pwszHttpTimeStamp;
        public IntPtr psRequest;
        public SIGNER_DIGEST_SIGN_INFO* pSignCallBack;
        public SIGNER_CONTEXT* ppSignerContext;
        public IntPtr pCryptoPolicy;
        public IntPtr pReserved;
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct APPX_SIP_CLIENT_DATA
    {
        public unsafe SIGNER_SIGN_EX3_PARAMS* pSignerParams;
        public IntPtr pAppxSipState;

    }

    [type: UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate int SignCallback(
        [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr pCertContext,
        [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr pvExtra,
        [param: In, MarshalAs(UnmanagedType.U4)] uint algId,
        [param: In, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U1, SizeParamIndex = 4)] byte[] pDigestToSign,
        [param: In, MarshalAs(UnmanagedType.U4)] uint dwDigestToSign,
        [param: In, Out] ref CRYPT_INTEGER_BLOB blob
        );
}
