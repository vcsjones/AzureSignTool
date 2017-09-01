using System;
using System.Runtime.InteropServices;

namespace OpenSignTool.Interop
{
    internal static class mssign32
    {
        [method: DllImport(nameof(mssign32), EntryPoint = "SignerSignEx3", CallingConvention = CallingConvention.Winapi)]
        public static extern int SignerSignEx3
        (
            [param: In, MarshalAs(UnmanagedType.U4)] SignerSignEx3Flags dwFlags,
            [param: In] ref SIGNER_SUBJECT_INFO pSubjectInfo,
            [param: In] ref SIGNER_CERT pSignerCert,
            [param: In] ref SIGNER_SIGNATURE_INFO pSignatureInfo,
            [param: In] IntPtr pProviderInfo,
            [param: In] IntPtr dwTimestampFlags,
            [param: In] IntPtr pszTimestampAlgorithmOid,
            [param: In] IntPtr pwszHttpTimeStamp,
            [param: In] IntPtr psRequest,
            [param: In] IntPtr pSipData,
            [param: In, Out] ref SIGNER_CONTEXT ppSignerContext,
            [param: In] IntPtr pCryptoPolicy,
            [param: In, Out] ref SIGN_INFO pSignInfo,
            [param: In] IntPtr pReserved
        );
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct SIGNER_CONTEXT
    {
        public uint cbSize;
        public uint cbBlob;
        public IntPtr pbBlob;

    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct SIGNER_PROVIDER_INFO
    {
        public uint cbSize;
        [field: MarshalAs(UnmanagedType.LPWStr)]
        public string pwszProviderName;

        public uint dwProviderType;
        public uint dwKeySpec;
        public uint dwPvkChoice;
        public SIGNER_PROVIDER_INFO_UNION union;
    }

    internal enum PvkUnionChoice : uint
    {
        PVK_TYPE_FILE_NAME = 0x01,
        PVK_TYPE_KEYCONTAINER = 0x02
    }

    [type: StructLayout(LayoutKind.Explicit)]
    internal struct SIGNER_PROVIDER_INFO_UNION
    {
        [field: MarshalAs(UnmanagedType.LPWStr), FieldOffset(0)]
        public string pwszPvkFileName;

        [field: MarshalAs(UnmanagedType.LPWStr), FieldOffset(0)]
        public string pwszKeyContainer;
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct SIGNER_SIGNATURE_INFO
    {
        public uint cbSize;
        public uint algidHash;
        public SignerSignatureInfoAttrChoice dwAttrChoice;
        public SIGNER_SIGNATURE_INFO_UNION attrAuthUnion;
        public IntPtr psAuthenticated;
        public IntPtr psUnauthenticated;
    }

    [type: StructLayout(LayoutKind.Explicit)]
    internal struct SIGNER_SIGNATURE_INFO_UNION
    {
        [field: FieldOffset(0)]
        public IntPtr pAttrAuthcode;
    }

    internal enum SignerSignatureInfoAttrChoice : uint
    {
        SIGNER_AUTHCODE_ATTR = 1,
        SIGNER_NO_ATTR = 0
    }


    [type: StructLayout(LayoutKind.Sequential)]
    internal struct SIGNER_CERT
    {
        public uint cbSize;
        public SignerCertChoice dwCertChoice;
        public SIGNER_CERT_UNION union;
        public IntPtr hwnd;
    }

    [type: StructLayout(LayoutKind.Explicit)]
    internal struct SIGNER_CERT_UNION
    {
        [field: MarshalAs(UnmanagedType.SysInt), FieldOffset(0)]
        public IntPtr pSpcChainInfo;
    }

    internal enum SignerCertChoice : uint
    {
        SIGNER_CERT_SPC_FILE = 1,
        SIGNER_CERT_STORE = 2,
        SIGNER_CERT_SPC_CHAIN = 3
    }

    [type: Flags]
    internal enum SignerSignEx3Flags : uint
    {
        NONE = 0x0,
        SPC_EXC_PE_PAGE_HASHES_FLAG = 0x010,
        SPC_INC_PE_IMPORT_ADDR_TABLE_FLAG = 0x020,
        SPC_INC_PE_DEBUG_INFO_FLAG = 0x040,
        SPC_INC_PE_RESOURCES_FLAG = 0x080,
        SPC_INC_PE_PAGE_HASHES_FLAG = 0x100,
        UNDOCUMENTED = 0X400,
        SIG_APPEND = 0x1000
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct SIGNER_SUBJECT_INFO
    {
        public uint cbSize;
        public unsafe uint* pdwIndex;
        public SignerSubjectInfoUnionChoice dwSubjectChoice;
        public SIGNER_SUBJECT_INFO_UNION unionInfo;
    }

    [type: StructLayout(LayoutKind.Explicit)]
    internal unsafe struct SIGNER_SUBJECT_INFO_UNION
    {
        [FieldOffset(0)]
        public IntPtr file;
        //TODO: we don't support signing blobs here.
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct SIGNER_FILE_INFO
    {
        public uint cbSize;
        public IntPtr pwszFileName;
        public IntPtr hFile;
    }

    internal enum SignerSubjectInfoUnionChoice : uint
    {
        SIGNER_SUBJECT_BLOB = 0x02,
        SIGNER_SUBJECT_FILE = 0x01
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct SIGN_INFO
    {
        public uint cbSize;

        [MarshalAs(UnmanagedType.FunctionPtr)]
        public SignCallback callback;

        public IntPtr pvOpaque;
    }


    [type: StructLayout(LayoutKind.Sequential)]
    internal struct CRYPTOAPI_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct SIGNER_ATTR_AUTHCODE
    {
        public uint cbSize;
        public uint fCommercial;
        public uint fIndividual;

        public IntPtr pwszName;
        public IntPtr pwszInfo;
    }

    [type: UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate int SignCallback(
        [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr pCertContext,
        [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr pvExtra,
        [param: In, MarshalAs(UnmanagedType.U4)] uint algId,
        [param: In, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U1, SizeParamIndex = 4)] byte[] pDigestToSign,
        [param: In, MarshalAs(UnmanagedType.U4)] uint dwDigestToSign,
        [param: Out] out CRYPTOAPI_BLOB blob
        );
}
