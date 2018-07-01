using AzureSignTool.Interop;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace AzureSignTool
{
    internal class SipExtensionFactory
    {
        public static SipExtension GetSipData(
            string filePath,
            SignerSignEx3Flags flags,
            PrimitiveStructureOutManager contextReceiver,
            SignerSignTimeStampFlags timestampFlags,
            AuthenticodeSignerCertStoreInfo storeInfo,
            string timestampUrl,
            string timestampAlgorithmOid,
            SignCallback callback,
            HashAlgorithmName fileDigestAlgorithm,
            AuthenticodeSignerFile fileInfo,
            AuthenticodeSignerAttributes attributes
            )
        {
            var extension = Path.GetExtension(filePath).ToLower();
            switch (extension)
            {
                case ".msix":
                case ".appx":
                case ".eappx":
                case ".appxbundle":
                case ".eappxbundle":
                    return new AppxSipExtension(flags, contextReceiver, timestampFlags, storeInfo, timestampUrl, timestampAlgorithmOid, callback, fileDigestAlgorithm, fileInfo, attributes);
                default:
                    return new SipExtension(flags, contextReceiver, timestampFlags, storeInfo, timestampUrl, timestampAlgorithmOid, callback, fileDigestAlgorithm, fileInfo, attributes);
            }
        }
    }

    internal class AppxSipExtension : SipExtension
    {
        private IntPtr _paramsHandle;
        private IntPtr _extraHandle;

        public AppxSipExtension(SignerSignEx3Flags flags,
            PrimitiveStructureOutManager contextReceiver,
            SignerSignTimeStampFlags timestampFlags,
            AuthenticodeSignerCertStoreInfo storeInfo,
            string timestampUrl,
            string timestampAlgorithmOid,
            SignCallback callback,
            HashAlgorithmName fileDigestAlgorithm,
            AuthenticodeSignerFile fileInfo,
            AuthenticodeSignerAttributes attributes)
            : base(flags, contextReceiver, timestampFlags, storeInfo, timestampUrl, timestampAlgorithmOid, callback, fileDigestAlgorithm, fileInfo, attributes)
        {

            var paramsStructure = new SIGNER_SIGN_EX3_PARAMS
            {
                dwFlags = ModifyFlags(flags),
                dwTimestampFlags = timestampFlags,
                pCryptoPolicy = IntPtr.Zero,
                pProviderInfo = IntPtr.Zero,
                ppSignerContext = contextReceiver.Handle,
                pReserved = IntPtr.Zero,
                psRequest = IntPtr.Zero,
                pwszHttpTimeStamp = TimestampUrlHandle,
                pszTimestampAlgorithmOid = TimestampAlgorithmOidHandle,
                pSignerCert = SignerCertHandle,
                pSubjectInfo = SubjectInfoHandle,
                pSignatureInfo = SignatureInfoHandle,
                pSignCallBack = SignInfoHandle
            };


            _paramsHandle = Marshal2.AllocHGlobal<SIGNER_SIGN_EX3_PARAMS>();
            Marshal.StructureToPtr(paramsStructure, _paramsHandle, false);

            var extraStructure = new APPX_SIP_CLIENT_DATA
            {
                pSignerParams = _paramsHandle
            };

            _extraHandle = Marshal2.AllocHGlobal<APPX_SIP_CLIENT_DATA>();
            Marshal.StructureToPtr(extraStructure, _extraHandle, false);

            SipDataHandle = _extraHandle;
        }

        public override void Dispose()
        {
            base.Dispose();
            var clientData = Marshal.PtrToStructure<APPX_SIP_CLIENT_DATA>(_extraHandle);
            if (clientData.pAppxSipState != IntPtr.Zero)
            {
                Marshal.Release(clientData.pAppxSipState);
            }
            Marshal2.DestroyAndFreeHGlobal<SIGNER_SIGN_EX3_PARAMS>(ref _paramsHandle);
            Marshal2.DestroyAndFreeHGlobal<APPX_SIP_CLIENT_DATA>(ref _extraHandle);
        }

        public override SignerSignEx3Flags ModifyFlags(SignerSignEx3Flags flags)
        {
            flags &= ~SignerSignEx3Flags.SPC_INC_PE_PAGE_HASHES_FLAG;
            flags |= SignerSignEx3Flags.SPC_EXC_PE_PAGE_HASHES_FLAG;
            return flags;
        }
    }

    internal class SipExtension : IDisposable
    {
        public IntPtr SipDataHandle { get; protected set; } = IntPtr.Zero;

        public virtual SignerSignEx3Flags ModifyFlags(SignerSignEx3Flags flags) => flags;

        public IntPtr TimestampUrlHandle { get; private set; }
        public IntPtr TimestampAlgorithmOidHandle { get; private set; }

        private IntPtr _signInfoHandle, _signatureInfoHandle, _subjectInfoHandle, _signerCertHandle;

        public ref IntPtr SignInfoHandle => ref _signInfoHandle;
        public ref IntPtr SignatureInfoHandle => ref _signatureInfoHandle;
        public ref IntPtr SubjectInfoHandle => ref _subjectInfoHandle;
        public ref IntPtr SignerCertHandle => ref _signerCertHandle;


        public SipExtension(
            SignerSignEx3Flags flags,
            PrimitiveStructureOutManager contextReceiver,
            SignerSignTimeStampFlags timestampFlags,
            AuthenticodeSignerCertStoreInfo storeInfo,
            string timestampUrl,
            string timestampAlgorithmOid,
            SignCallback callback,
            HashAlgorithmName fileDigestAlgorithm,
            AuthenticodeSignerFile fileInfo,
            AuthenticodeSignerAttributes attributes
            )
        {
            TimestampUrlHandle = Marshal.StringToHGlobalUni(timestampUrl);
            TimestampAlgorithmOidHandle = Marshal.StringToHGlobalAnsi(timestampAlgorithmOid);
            var callbackPtr = Marshal.GetFunctionPointerForDelegate(callback);

            var signInfo = new SIGN_INFO(callbackPtr);

            var subject = new SIGNER_SUBJECT_INFO(
                dwSubjectChoice: SignerSubjectInfoUnionChoice.SIGNER_SUBJECT_FILE,
                pdwIndex: NativeConstants.ZeroDWORD,
                unionInfo: new SIGNER_SUBJECT_INFO_UNION(fileInfo.Handle)
            );
            var signerCert = new SIGNER_CERT(
                dwCertChoice: SignerCertChoice.SIGNER_CERT_STORE,
                union: new SIGNER_CERT_UNION
                {
                    pSpcChainInfo = storeInfo.Handle
                }
            );
            var signatureInfo = new SIGNER_SIGNATURE_INFO(
                algidHash: AlgorithmTranslator.HashAlgorithmToAlgId(fileDigestAlgorithm),
                psAuthenticated: IntPtr.Zero,
                psUnauthenticated: IntPtr.Zero,
                dwAttrChoice: SignerSignatureInfoAttrChoice.SIGNER_AUTHCODE_ATTR,
                attrAuthUnion: new SIGNER_SIGNATURE_INFO_UNION
                {
                    pAttrAuthcode = attributes.Handle
                }
            );
            SignInfoHandle = Marshal2.AllocHGlobal<SIGN_INFO>();
            Marshal.StructureToPtr(signInfo, SignInfoHandle, false);

            SignatureInfoHandle = Marshal2.AllocHGlobal<SIGNER_SIGNATURE_INFO>();
            Marshal.StructureToPtr(signatureInfo, SignatureInfoHandle, false);

            SignerCertHandle = Marshal2.AllocHGlobal<SIGNER_CERT>();
            Marshal.StructureToPtr(signerCert, SignerCertHandle, false);

            SubjectInfoHandle = Marshal2.AllocHGlobal<SIGNER_SUBJECT_INFO>();
            Marshal.StructureToPtr(subject, SubjectInfoHandle, false);
        }

        public virtual void Dispose()
        {
            Marshal.FreeHGlobal(TimestampUrlHandle);
            Marshal.FreeHGlobal(TimestampAlgorithmOidHandle);
            Marshal2.DestroyAndFreeHGlobal<SIGN_INFO>(ref SignInfoHandle);
            Marshal2.DestroyAndFreeHGlobal<SIGNER_SIGNATURE_INFO>(ref SignatureInfoHandle);
            Marshal2.DestroyAndFreeHGlobal<SIGNER_CERT>(ref SignerCertHandle);
            Marshal2.DestroyAndFreeHGlobal<SIGNER_SUBJECT_INFO>(ref SubjectInfoHandle);
        }
    }
}
