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
        private readonly GCHandle _paramsHandle;
        private readonly GCHandle _extraHandle;

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

            _paramsHandle = GCHandle.Alloc(paramsStructure, GCHandleType.Pinned);

            var extraStructure = new APPX_SIP_CLIENT_DATA
            {
                pSignerParams = _paramsHandle.AddrOfPinnedObject()
            };

            _extraHandle = GCHandle.Alloc(extraStructure, GCHandleType.Pinned);
            SipDataHandle = _extraHandle.AddrOfPinnedObject();
        }

        public override void Dispose()
        {
            base.Dispose();
            _paramsHandle.Free();
            _extraHandle.Free();
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

        public IntPtr TimestampUrlHandle { get; }
        public IntPtr TimestampAlgorithmOidHandle { get; }

        private readonly GCHandle _signInfoHandle;
        private readonly GCHandle _signatureInfoHandle;
        private readonly GCHandle _signerCertHandle;
        private readonly GCHandle _subjectInfoHandle;

        public IntPtr SignInfoHandle => _signInfoHandle.AddrOfPinnedObject();
        public IntPtr SignatureInfoHandle => _signatureInfoHandle.AddrOfPinnedObject();
        public IntPtr SubjectInfoHandle => _subjectInfoHandle.AddrOfPinnedObject();
        public IntPtr SignerCertHandle => _signerCertHandle.AddrOfPinnedObject();


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
            _signInfoHandle = GCHandle.Alloc(signInfo, GCHandleType.Pinned);
            _signatureInfoHandle = GCHandle.Alloc(signatureInfo, GCHandleType.Pinned);
            _signerCertHandle = GCHandle.Alloc(signerCert, GCHandleType.Pinned);
            _subjectInfoHandle = GCHandle.Alloc(subject, GCHandleType.Pinned);
        }

        public virtual void Dispose()
        {
            Marshal.FreeHGlobal(TimestampUrlHandle);
            Marshal.FreeHGlobal(TimestampAlgorithmOidHandle);
            _signInfoHandle.Free();
            _signatureInfoHandle.Free();
            _signerCertHandle.Free();
            _subjectInfoHandle.Free();
        }
    }
}
