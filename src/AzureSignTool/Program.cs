using System;
using System.Runtime.InteropServices;
using AzureSign.Core;
using McMaster.Extensions.CommandLineUtils;

using static AzureSignTool.HRESULT;

namespace AzureSignTool
{
    class Program
    {
        static int Main(string[] args)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Console.Error.WriteLine("Azure Sign Tool is only supported on Windows.");
                return E_PLATFORMNOTSUPPORTED;
            }

            AuthenticodeKeyVaultSigner.Initialize();

            var application = new CommandLineApplication<Program>(throwOnUnexpectedArg: false);
            application.ValueParsers.Add(new HashAlgorithmNameValueParser());
            application.Command<SignCommand>("sign", throwOnUnexpectedArg: false, configuration: config =>
            {
                config.Description = "Signs a file.";
                config.Conventions.UseDefaultConventions();
            });
            return application.Execute(args);
        }
    }
}
