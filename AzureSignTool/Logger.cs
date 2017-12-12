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

        public ILogger Scoped() => new ScopedConsoleLogger(this);

        private class ScopedConsoleLogger : ILogger
        {
            private ILogger _parent;
            private static int _nextScopeId = 0;
            private int _scopeId = Interlocked.Increment(ref _nextScopeId);

            public ScopedConsoleLogger(ILogger parent)
            {
                _parent = parent;
            }

            public LogLevel Level
            {
                get => _parent.Level;
                set => _parent.Level = value;
            }

            public void Dispose()
            {
                _parent.Dispose();
            }

            public void Log(string message, LogLevel level)
            {
                if (level <= Level)
                {
                    lock (_sync)
                    {
                        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}][{_scopeId}] {message}");
                    }
                }
            }

            public ILogger Scoped() => _parent.Scoped();
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

        public ILogger Scoped() => this;
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
        ILogger Scoped();

    }

    public enum LogLevel
    {
        Quiet = 0,
        Normal = 1,
        Verbose = 2
    }

}
