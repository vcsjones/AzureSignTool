using System;
using System.Runtime.InteropServices;

namespace AzureSign.Core.Interop
{
    internal static class mssign32
    {
        [method: DllImport(nameof(mssign32), EntryPoint = "SignerSignEx3", CallingConvention = CallingConvention.Winapi)]
        public static unsafe extern int SignerSignEx3
        (
            [param: In, MarshalAs(UnmanagedType.U4)] SignerSignEx3Flags dwFlags,
            [param: In] SIGNER_SUBJECT_INFO* pSubjectInfo,
            [param: In] SIGNER_CERT* pSignerCert,
            [param: In] SIGNER_SIGNATURE_INFO* pSignatureInfo,
            [param: In] IntPtr pProviderInfo,
            [param: In] SignerSignTimeStampFlags dwTimestampFlags,
            [param: In] byte* pszTimestampAlgorithmOid,
            [param: In] char* pwszHttpTimeStamp,
            [param: In] IntPtr psRequest,
            [param: In] void* pSipData,
            [param: In] IntPtr* ppSignerContext,
            [param: In] IntPtr pCryptoPolicy,
            [param: In] SIGN_INFO* pSignInfo,
            [param: In] IntPtr pReserved
        );

        [method: DllImport(nameof(mssign32), CallingConvention = CallingConvention.Winapi)]
        public static extern int SignerFreeSignerContext(
            [param: In] IntPtr pSignerContext
        );
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

        public SIGNER_SIGNATURE_INFO(uint algidHash,
            SignerSignatureInfoAttrChoice dwAttrChoice,
            SIGNER_SIGNATURE_INFO_UNION attrAuthUnion,
            IntPtr psAuthenticated,
            IntPtr psUnauthenticated
            )
        {
            cbSize = (uint)Marshal.SizeOf<SIGNER_SIGNATURE_INFO>();
            this.algidHash = algidHash;
            this.dwAttrChoice = dwAttrChoice;
            this.attrAuthUnion = attrAuthUnion;
            this.psAuthenticated = psAuthenticated;
            this.psUnauthenticated = psUnauthenticated;
        }
    }

    [type: StructLayout(LayoutKind.Explicit)]
    internal unsafe struct SIGNER_SIGNATURE_INFO_UNION
    {
        public SIGNER_SIGNATURE_INFO_UNION(SIGNER_ATTR_AUTHCODE* pAttrAuthcode)
        {
            this.pAttrAuthcode = pAttrAuthcode;
        }

        [field: FieldOffset(0)]
        public SIGNER_ATTR_AUTHCODE* pAttrAuthcode;
    }

    internal enum SignerSignTimeStampFlags : uint
    {
        SIGNER_TIMESTAMP_AUTHENTICODE = 1,
        SIGNER_TIMESTAMP_RFC3161 = 2,
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

        public SIGNER_CERT(SignerCertChoice dwCertChoice, SIGNER_CERT_UNION union)
        {
            this.dwCertChoice = dwCertChoice;
            this.union = union;
            hwnd = default;
            cbSize = (uint)Marshal.SizeOf<SIGNER_CERT>();
        }
    }

    [type: StructLayout(LayoutKind.Explicit)]
    internal unsafe struct SIGNER_CERT_UNION
    {
        public SIGNER_CERT_UNION(SIGNER_CERT_STORE_INFO* certStoreInfo)
        {
            pSpcChainInfo = certStoreInfo;
        }

        [field: FieldOffset(0)]
        public SIGNER_CERT_STORE_INFO* pSpcChainInfo;
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
        SIGN_CALLBACK_UNDOCUMENTED = 0X400,
        SIG_APPEND = 0x1000
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal unsafe struct SIGNER_SUBJECT_INFO
    {
        public uint cbSize;
        public uint* pdwIndex;
        public SignerSubjectInfoUnionChoice dwSubjectChoice;
        public SIGNER_SUBJECT_INFO_UNION unionInfo;

        public SIGNER_SUBJECT_INFO(uint* pdwIndex, SignerSubjectInfoUnionChoice dwSubjectChoice, SIGNER_SUBJECT_INFO_UNION unionInfo)
        {
            cbSize = (uint)Marshal.SizeOf<SIGNER_SUBJECT_INFO>();
            this.pdwIndex = pdwIndex;
            this.dwSubjectChoice = dwSubjectChoice;
            this.unionInfo = unionInfo;
        }
    }

    [type: StructLayout(LayoutKind.Explicit)]
    internal unsafe struct SIGNER_SUBJECT_INFO_UNION
    {
        [FieldOffset(0)]
        public SIGNER_FILE_INFO* file;

        public SIGNER_SUBJECT_INFO_UNION(SIGNER_FILE_INFO* file)
        {
            this.file = file;
        }
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal unsafe struct SIGNER_FILE_INFO
    {
        public uint cbSize;
        public char* pwszFileName;
        public IntPtr hFile;

        public SIGNER_FILE_INFO(char* pwszFileName, IntPtr hFile)
        {
            cbSize = (uint)Marshal.SizeOf<SIGNER_FILE_INFO>();
            this.pwszFileName = pwszFileName;
            this.hFile = hFile;
        }
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

        public IntPtr callback;

        public IntPtr pvOpaque;

        public SIGN_INFO(IntPtr callback)
        {
            cbSize = (uint)Marshal.SizeOf<SIGN_INFO>();
            this.callback = callback;
            pvOpaque = default;
        }
    }


    [type: StructLayout(LayoutKind.Sequential)]
    internal struct CRYPTOAPI_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal unsafe struct SIGNER_ATTR_AUTHCODE
    {
        public uint cbSize;
        public uint fCommercial;
        public uint fIndividual;

        public char* pwszName;
        public char* pwszInfo;

        public SIGNER_ATTR_AUTHCODE(char* pwszName, char* pwszInfo)
        {
            cbSize = (uint)Marshal.SizeOf<SIGNER_ATTR_AUTHCODE>();
            fCommercial = 0;
            fIndividual = 0;
            this.pwszName = pwszName;
            this.pwszInfo = pwszInfo;
        }
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal unsafe struct SIGNER_SIGN_EX3_PARAMS
    {
        public SignerSignEx3Flags dwFlags;
        public SIGNER_SUBJECT_INFO* pSubjectInfo;
        public SIGNER_CERT* pSignerCert;
        public SIGNER_SIGNATURE_INFO* pSignatureInfo;
        public IntPtr pProviderInfo;
        public SignerSignTimeStampFlags dwTimestampFlags;
        public byte* pszTimestampAlgorithmOid;
        public char* pwszHttpTimeStamp;
        public IntPtr psRequest;
        public SIGN_INFO* pSignCallBack;
        public IntPtr* ppSignerContext;
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
        [param: In, Out] ref CRYPTOAPI_BLOB blob
        );
}
