using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace No2SQL.Tests.Infrastructure;

/// <summary>Keeps every log entry the application writes, with its category, for assertions.</summary>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<LogEntry> _entries = new();

    public IReadOnlyList<LogEntry> Entries => [.. _entries];

    public IEnumerable<LogEntry> InCategory(string category) => Entries.Where(e => e.Category == category);

    /// <summary>All entries as text, exception text included, the way a console log would show them.</summary>
    public string AllText => string.Join("\n", Entries.Select(e => $"{e.Category} {e.Message} {e.Exception}"));

    public ILogger CreateLogger(string categoryName) => new Logger(categoryName, _entries);

    public void Dispose()
    {
    }

    public sealed record LogEntry(string Category, LogLevel Level, string Message, Exception? Exception);

    private sealed class Logger(string category, ConcurrentQueue<LogEntry> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            entries.Enqueue(new LogEntry(category, logLevel, formatter(state, exception), exception));
    }
}
