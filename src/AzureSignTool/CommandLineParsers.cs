using System;
using System.Globalization;
using System.Security.Cryptography;
using McMaster.Extensions.CommandLineUtils.Abstractions;

namespace AzureSignTool
{
    internal class HashAlgorithmNameValueParser : IValueParser
    {
        public Type TargetType => typeof(HashAlgorithmName);

        public object Parse(string argName, string value, CultureInfo culture) => new HashAlgorithmName(value?.ToUpperInvariant());
    }
}
