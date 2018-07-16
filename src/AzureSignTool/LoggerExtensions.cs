using Microsoft.Extensions.Logging;
using System;

namespace AzureSignTool
{
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
