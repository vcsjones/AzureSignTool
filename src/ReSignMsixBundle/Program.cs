using ReSignMsixBundle.CommandLineHelpers;

namespace ReSignMsixBundle;

/// <summary>The main program.</summary>
[SupportedOSPlatform("windows")] public class Program
{
    /// <summary>Main entry-point for this application.</summary>
    /// <param name="args">An array of command-line argument strings.</param>
    /// <returns>Exit-code for the process - 0 for success, else an error code.</returns>
    public static int Main(string[] args)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.Error.WriteLine("Azure Sign Tool is only supported on Windows.");
            return HRESULT.E_PLATFORMNOTSUPPORTED;
        }

        var application = new CommandLineApplication<ReSignMsixBundleApplication>();
        application.ValueParsers.Add(new HashAlgorithmNameValueParser());
        application.Command<ReSignCommand>("re-sign",
            config =>
            {
                config.Description = "Re-signs an MSIX bundle file and all the MSIX files in the bundle.";
            });
        application.VersionOptionFromAssemblyAttributes(typeof(Program).Assembly);
        application.Conventions.UseDefaultConventions();
        application.UnrecognizedArgumentHandling = UnrecognizedArgumentHandling.StopParsingAndCollect;
        return application.Execute(args);
    }
}
