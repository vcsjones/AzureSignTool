using Xunit;

namespace AzureSign.Core.Tests
{
    public class SipExtensionFactoryTests
    {
        [Theory]
        [InlineData(@"C:\foo.appx")]
        [InlineData(@"C:\foo.APPX")]
        [InlineData(@"C:\foo.eappx")]
        [InlineData(@"C:\foo.eaPPx")]
        [InlineData(@"C:\foo.appxbundle")]
        [InlineData(@"C:\foo.appxBUNDLE")]
        [InlineData(@"C:\foo.eappxbundle")]
        [InlineData(@"C:\foo.EAppxBUNDLE")]
        public void ShouldReturnAppxSipForAppxFiles(string path)
        {
            var kind = SipExtensionFactory.GetSipKind(path);
            Assert.Equal(SipKind.Appx, kind);
        }

        [Theory]
        [InlineData(@"C:\foo.msix")]
        [InlineData(@"C:\foo.MSIX")]
        [InlineData(@"C:\foo.emsix")]
        [InlineData(@"C:\foo.emSIx")]
        [InlineData(@"C:\foo.msixbundle")]
        [InlineData(@"C:\foo.msixBUNDLE")]
        [InlineData(@"C:\foo.emsixbundle")]
        [InlineData(@"C:\foo.EMSixBUNDLE")]
        public void ShouldReturnAppxSipForMsixFiles(string path)
        {
            var kind = SipExtensionFactory.GetSipKind(path);
            Assert.Equal(SipKind.Appx, kind);
        }

        [Theory]
        [InlineData(@"C:\foo.exe")]
        [InlineData(@"C:\foo.msi")]
        [InlineData(@"C:\foo.cab")]
        [InlineData(@"C:\foo.dll")]
        [InlineData(@"C:\foo.bin")]
        public void ShouldReturnNoneForOtherFileTypes(string path)
        {
            var kind = SipExtensionFactory.GetSipKind(path);
            Assert.Equal(SipKind.None, kind);
        }
    }
}
