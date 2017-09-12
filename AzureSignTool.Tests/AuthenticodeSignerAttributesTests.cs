using System;
using Xunit;

namespace AzureSignTool.Tests
{
    public class AuthenticodeSignerAttributesTests
    {

        [Fact]
        public void ShouldAcceptNullAndMarshalAsEmptyString()
        {
            using (var attributes = new AuthenticodeSignerAttributes(null, null))
            {
                Assert.NotEqual(IntPtr.Zero, attributes.Handle);
            }
        }

        [Fact]
        public void ShouldNotExplodeOnMultipleDisposes()
        {
            var attributes = new AuthenticodeSignerAttributes(null, null);
            attributes.Dispose();
            attributes.Dispose();
        }

        [Fact]
        public void ShouldZeroHandleOnDispose()
        {
            var attributes = new AuthenticodeSignerAttributes(null, null);
            Assert.NotEqual(IntPtr.Zero, attributes.Handle);
            attributes.Dispose();
            Assert.Equal(IntPtr.Zero, attributes.Handle);

        }
    }
}
