using Microsoft.Extensions.Logging;
using System;
using System.Threading;

namespace AzureSignTool
{
    public static class LoggerServiceLocator
    {
        private static ILogger _currentLogger;

        public static ILogger Current
        {
            get => _currentLogger;
            set
            {
                var old = Interlocked.Exchange(ref _currentLogger, value);
            }
        }
    }

    internal static class LoggerExtensions
    {
        private readonly static Func<ILogger, string, IDisposable> _itemScope;

        static LoggerExtensions()
        {
            _itemScope = LoggerMessage.DefineScope<string>("File: {Id}");
        }

        public static IDisposable FileNameScope(this ILogger logger, string fileName) => _itemScope(logger, fileName);
    }


}
