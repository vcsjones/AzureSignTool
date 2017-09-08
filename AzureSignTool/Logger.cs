using System;
using System.Threading;
using System.Threading.Tasks;

namespace AzureSignTool
{
    public sealed class ConsoleLogger : ILogger
    {
        public LogLevel Level { get; set; } = LogLevel.Normal;

        public void Dispose()
        {
        }

        public Task Log(string message, LogLevel level)
        {
            if (level <= Level)
            {
                Console.WriteLine(message);
            }
            return Task.CompletedTask;
        }
    }

    public sealed class NullLogger : ILogger
    {
        public LogLevel Level { get; set; }

        public void Dispose()
        {
        }

        public Task Log(string message, LogLevel level) => Task.CompletedTask;
    }


    public static class LoggerServiceLocator
    {
        private static ILogger _currentLogger = new NullLogger();

        public static ILogger Current
        {
            get => _currentLogger;
            set
            {
                var old = Interlocked.Exchange(ref _currentLogger, value);
                old?.Dispose();
            }
        }
    }

    public interface ILogger : IDisposable
    {
        LogLevel Level { get; set; }
        Task Log(string message, LogLevel level = LogLevel.Normal);

    }

    public enum LogLevel
    {
        Quiet = 0,
        Normal = 1,
        Verbose = 2
    }

}
