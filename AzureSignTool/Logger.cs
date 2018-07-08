using System;
using System.IO;
using System.Text;
using System.Threading;

namespace AzureSignTool
{
    public sealed class TextWriterLogger : ILogger
    {
        private static object _sync = new object();
        private readonly TextWriter _writer;
        private readonly TextWriterLogger _parent;
        private readonly int _scopeId = 0;
        private int _nextChildScopeId = 0;
        private readonly string _parentChain;

        public LogLevel Level { get; set; } = LogLevel.Normal;

        public TextWriterLogger(TextWriter writer)
        {
            _writer = writer;
            _parentChain = string.Empty;
        }

        private TextWriterLogger(TextWriterLogger parent) : this(parent._writer)
        {
            _parent = parent;
            _scopeId = Interlocked.Increment(ref parent._nextChildScopeId);
            _parentChain = parent._parentChain + $"[{_scopeId}]";
            Level = parent.Level;
        }

        public void Dispose()
        {
        }

        public void Log(string message, LogLevel level)
        {
            if (level <= Level)
            {
                lock (_sync)
                {
                    _writer.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}]{_parentChain} {message}");
                }
            }
        }

        public ILogger Scoped() => new TextWriterLogger(this);

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
