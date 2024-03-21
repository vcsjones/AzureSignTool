using System.Globalization;
using McMaster.Extensions.CommandLineUtils.Abstractions;

namespace ReSignMsixBundle.CommandLineHelpers;

internal class HashAlgorithmNameValueParser : IValueParser
{
    public object Parse(string? argName, string? value, CultureInfo culture)
    {
        return new HashAlgorithmName(value?.ToUpperInvariant());
    }

    public Type TargetType => typeof(HashAlgorithmName);
}
