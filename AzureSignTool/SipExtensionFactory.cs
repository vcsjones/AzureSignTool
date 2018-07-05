using System;
using System.IO;
using AzureSignTool.Interop;

namespace AzureSignTool
{
    internal enum SipKind
    {
        None,
        Appx
    }

    internal class SipExtensionFactory
    {
        public static SipKind GetSipKind(ReadOnlySpan<char> filePath)
        {
            var extension = Path.GetExtension(filePath);
            if (extension.Equals(".appx", StringComparison.OrdinalIgnoreCase))
            {
                return SipKind.Appx;
            }
            if (extension.Equals(".eappx", StringComparison.OrdinalIgnoreCase))
            {
                return SipKind.Appx;
            }
            if (extension.Equals(".appxbundle", StringComparison.OrdinalIgnoreCase))
            {
                return SipKind.Appx;
            }
            if (extension.Equals(".eappxbundle", StringComparison.OrdinalIgnoreCase))
            {
                return SipKind.Appx;
            }
            return SipKind.None;
        }
    }

    internal static class AppxSipExtension
    {
        public static unsafe void FillExtension(
            ref SignerSignEx3Flags flags,
            ref APPX_SIP_CLIENT_DATA clientData,
            SignerSignTimeStampFlags timestampFlags,
            SIGNER_SUBJECT_INFO* signerSubjectInfo,
            SIGNER_CERT* signerCert,
            SIGNER_SIGNATURE_INFO* signatureInfo,
            IntPtr* signerContext,
            char* timestampUrl,
            byte* timestampOid,
            SIGN_INFO* signInfo
        )
        {
            flags &= ~SignerSignEx3Flags.SPC_INC_PE_PAGE_HASHES_FLAG;
            flags |= SignerSignEx3Flags.SPC_EXC_PE_PAGE_HASHES_FLAG;
            clientData.pSignerParams->dwFlags = flags;
            clientData.pSignerParams->dwTimestampFlags = timestampFlags;
            clientData.pSignerParams->pSubjectInfo = signerSubjectInfo;
            clientData.pSignerParams->pSignerCert = signerCert;
            clientData.pSignerParams->pSignatureInfo = signatureInfo;
            clientData.pSignerParams->ppSignerContext = signerContext;
            clientData.pSignerParams->pwszHttpTimeStamp = timestampUrl;
            clientData.pSignerParams->pszTimestampAlgorithmOid = timestampOid;
            clientData.pSignerParams->pSignCallBack = signInfo;

        }
    }
}