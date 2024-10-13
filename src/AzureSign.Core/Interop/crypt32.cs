using System;
using System.Runtime.InteropServices;

namespace AzureSign.Core.Interop
{
    internal static class crypt32
    {
        [return: MarshalAs(UnmanagedType.Bool)]
        [method: DllImport(nameof(crypt32), CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        public static extern bool CertCloseStore
        (
            [In, MarshalAs(UnmanagedType.SysInt)] IntPtr hCertStore,
            [In, MarshalAs(UnmanagedType.U4)] CertCloreStoreFlags dwFlags
        );

        [return: MarshalAs(UnmanagedType.SysInt)]
        [method: DllImport(nameof(crypt32), CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        public static extern IntPtr CertOpenStore
        (
            [In, MarshalAs(UnmanagedType.LPStr)] string lpszStoreProvider,
            [In, MarshalAs(UnmanagedType.U4)] CertEncodingType CertEncodingType,
            [In, MarshalAs(UnmanagedType.SysInt)] IntPtr hCryptProv,
            [In, MarshalAs(UnmanagedType.U4)] CertOpenStoreFlags dwFlags,
            [In, MarshalAs(UnmanagedType.SysInt)] IntPtr pvPara
        );
    }

    [type: StructLayout(LayoutKind.Sequential)]
    internal struct SIGNER_CERT_STORE_INFO(IntPtr pSigningCert, SignerCertStoreInfoFlags dwCertPolicy, IntPtr hCertStore)
    {
        public uint cbSize = (uint)Marshal.SizeOf<SIGNER_CERT_STORE_INFO>();
        public IntPtr pSigningCert = pSigningCert;
        public SignerCertStoreInfoFlags dwCertPolicy = dwCertPolicy;
        public IntPtr hCertStore = hCertStore;
    }

    [type: Flags]
    internal enum SignerCertStoreInfoFlags
    {

        SIGNER_CERT_POLICY_CHAIN = 0x02,
        SIGNER_CERT_POLICY_CHAIN_NO_ROOT = 0x08,
        SIGNER_CERT_POLICY_STORE = 0x01
    }

    [type: Flags]
    internal enum CertOpenStoreFlags : uint
    {
        NONE = 0,
        CERT_STORE_NO_CRYPT_RELEASE_FLAG = 0x00000001,
        CERT_STORE_SET_LOCALIZED_NAME_FLAG = 0x00000002,
        CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG = 0x00000004,
        CERT_STORE_DELETE_FLAG = 0x00000010,
        CERT_STORE_UNSAFE_PHYSICAL_FLAG = 0x00000020,
        CERT_STORE_SHARE_STORE_FLAG = 0x00000040,
        CERT_STORE_SHARE_CONTEXT_FLAG = 0x00000080,
        CERT_STORE_MANIFOLD_FLAG = 0x00000100,
        CERT_STORE_ENUM_ARCHIVED_FLAG = 0x00000200,
        CERT_STORE_UPDATE_KEYID_FLAG = 0x00000400,
        CERT_STORE_BACKUP_RESTORE_FLAG = 0x00000800,
        CERT_STORE_READONLY_FLAG = 0x00008000,
        CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000,
        CERT_STORE_CREATE_NEW_FLAG = 0x00002000,
        CERT_STORE_MAXIMUM_ALLOWED_FLAG = 0x00001000,
    }

    [type: Flags]
    internal enum CertCloreStoreFlags : uint
    {
        NONE = 0,
        CERT_CLOSE_STORE_FORCE_FLAG = 0x00000001,
        CERT_CLOSE_STORE_CHECK_FLAG = 0x00000002,
    }

    internal enum CertEncodingType : uint
    {
        NONE = 0,
        X509_ASN_ENCODING = 0x1,
        PKCS_7_ASN_ENCODING = 0x10000
    }
}
