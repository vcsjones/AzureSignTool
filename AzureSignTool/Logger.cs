using System;
using System.Threading;

namespace AzureSignTool
{
    public sealed class ConsoleLogger : ILogger
    {
        public LogLevel Level { get; set; } = LogLevel.Normal;
        private static object _sync = new object();

        public void Dispose()
        {
        }

        public void Log(string message, LogLevel level)
        {
            if (level <= Level)
            {
                lock (_sync)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {message}");
                }
            }
        }
    }

    public sealed class NullLogger : ILogger
    {
        public LogLevel Level { get; set; }

        public void Dispose()
        {
        }

        public void Log(string message, LogLevel level)
        {
        }
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
        void Log(string message, LogLevel level = LogLevel.Normal);

    }

    public enum LogLevel
    {
        Quiet = 0,
        Normal = 1,
        Verbose = 2
    }

}
