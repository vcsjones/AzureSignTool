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
        private readonly static Func<ILogger, int, IDisposable> _itemScope;

        static LoggerExtensions()
        {
            _itemScope = LoggerMessage.DefineScope<int>("Id:{Id}");
        }

        public static IDisposable ItemIdScope(this ILogger logger, int id) => _itemScope(logger, id);
    }


}
