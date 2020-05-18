using System;
using System.Runtime.InteropServices;
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
            var application = new CommandLineApplication<Program>();
            application.ValueParsers.Add(new HashAlgorithmNameValueParser());
            application.ShowHint();
            application.Command<SignCommand>("sign", config =>
            {
                config.Description = "Signs a file.";
                config.Conventions.UseDefaultConventions();
            });
            application.Command(string.Empty, config => {
                application.ShowHelp();
                application.ShowHint();
            });
            application.UnrecognizedArgumentHandling = UnrecognizedArgumentHandling.StopParsingAndCollect;
            return application.Execute(args);
        }
    }
}
