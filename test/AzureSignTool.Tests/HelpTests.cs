using System;
using System.IO;
using Xunit;

namespace AzureSignTool.Tests
{
    public class HelpTests
    {
        private static readonly object _sync = new object();

        [Fact]
        public void BlankInputShouldShowHelpOutput()
        {
            (string StdOut, string StdErr, int ExitCode) = Capture(() => {
                return Program.Main(new string[0]);
            });

            Assert.Contains("Usage:", StdOut);
            Assert.Equal(1, ExitCode);
        }

        [Fact]
        public void BlankInputForSignCommandShouldShowHelpOutput()
        {
            (string StdOut, string StdErr, int ExitCode) = Capture(() => {
                return Program.Main(new string[] { "sign" });
            });

            Assert.Contains("--help", StdOut);
            Assert.NotEqual(0, ExitCode);
        }

        [Fact]
        public void ShowVersionOnOutputForHelp()
        {
            (string StdOut, string StdErr, int ExitCode) = Capture(() => {
                return Program.Main([]);
            });

            Assert.Matches(@"^\d\.\d\.\d", StdOut);
            Assert.NotEqual(0, ExitCode);
        }

        [Fact]
        public void ShowVersionOnOutputVersionArg()
        {
            (string StdOut, string StdErr, int ExitCode) = Capture(() => {
                return Program.Main(["--version"]);
            });

            // This is from https://semver.org/
            const string SemVerRegex = @"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$";
            Assert.Matches(SemVerRegex, StdOut);
            Assert.Equal(0, ExitCode);
        }

        private static (string StdOut, string StdErr, T Result) Capture<T>(Func<T> act)
        {
            lock (_sync)
            {
                TextWriter oldStdOutWriter = Console.Out;
                TextWriter oldStdErrWriter = Console.Error;
                StringWriter stdOutWriter = new StringWriter();
                StringWriter stdErrWriter = new StringWriter();

                try
                {
                    Console.SetOut(stdOutWriter);
                    Console.SetError(stdErrWriter);
                    T result = act();
                    return (stdOutWriter.ToString(), stdErrWriter.ToString(), result);
                }
                finally
                {
                    Console.SetOut(oldStdOutWriter);
                    Console.SetError(oldStdErrWriter);
                }
            }

        }
    }
}
