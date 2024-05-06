using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace AzureSignTool.Tests
{
    public class HelpTests
    {
        private static readonly SemaphoreSlim _sync = new(1, 1);

        [Fact]
        public async Task BlankInputShouldShowHelpOutput()
        {
            (string StdOut, string StdErr, int ExitCode) = await Capture(async () => {
                return await Program.Main(new string[0]);
            });

            Assert.Contains("usage.", StdErr);
            Assert.Equal(1, ExitCode);
        }

        [Fact]
        public async Task BlankInputForSignCommandShouldShowHelpOutput()
        {
            (string StdOut, string StdErr, int ExitCode) = await Capture(async () => {
                return await Program.Main(new string[] { "sign" });
            });

            Assert.Contains("--help", StdErr);
            Assert.NotEqual(0, ExitCode);
        }

        [Fact]
        public async Task ShowVersionOnOutputVersionArg()
        {
            (string StdOut, string StdErr, int ExitCode) = await Capture(async () => {
                return await Program.Main(["--version"]);
            });

            Assert.Matches(@"^\d\.\d\.\d", StdOut);
            Assert.Equal(0, ExitCode);
        }

        private static async Task<(string StdOut, string StdErr, T Result)> Capture<T>(Func<ValueTask<T>> act)
        {
            try
            {
                await _sync.WaitAsync();

                TextWriter oldStdOutWriter = Console.Out;
                TextWriter oldStdErrWriter = Console.Error;
                StringWriter stdOutWriter = new StringWriter();
                StringWriter stdErrWriter = new StringWriter();

                try
                {
                    Console.SetOut(stdOutWriter);
                    Console.SetError(stdErrWriter);
                    T result = await act();
                    return (stdOutWriter.ToString(), stdErrWriter.ToString(), result);
                }
                finally
                {
                    Console.SetOut(oldStdOutWriter);
                    Console.SetError(oldStdErrWriter);
                }
            }
            finally
            {
                _sync.Release();
            }
        }
    }
}
