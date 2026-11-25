using System.Text;

namespace No2SQL.Security;

/// <summary>
/// A TextWriter that masks every secret the <see cref="SecretRedactor"/> knows before writing to the
/// stream underneath. Installed as Console.Error (and, in HTTP mode, Console.Out) before the host is
/// built, so the console logger, the host's own messages and every Console.Error.WriteLine go through it.
/// </summary>
/// <remarks>
/// Text is masked per call. The console logger and Console.WriteLine write a whole message per call;
/// single characters are passed through as they are, since a secret cannot be recognised in one.
/// </remarks>
internal sealed class RedactingTextWriter(TextWriter inner, SecretRedactor redactor) : TextWriter(inner.FormatProvider)
{
    public override Encoding Encoding => inner.Encoding;

    [System.Diagnostics.CodeAnalysis.AllowNull]
    public override string NewLine
    {
        get => inner.NewLine;
        set => inner.NewLine = value;
    }

    public override void Write(char value) => inner.Write(value);

    public override void Write(string? value)
    {
        if (value is not null)
        {
            inner.Write(redactor.Redact(value));
        }
    }

    public override void Write(char[] buffer, int index, int count) => Write(new string(buffer, index, count));

    public override void Write(ReadOnlySpan<char> buffer) => Write(new string(buffer));

    public override void WriteLine() => inner.WriteLine();

    public override void WriteLine(string? value) => inner.WriteLine(value is null ? null : redactor.Redact(value));

    public override void WriteLine(ReadOnlySpan<char> buffer) => WriteLine(new string(buffer));

    public override Task WriteAsync(char value) => inner.WriteAsync(value);

    public override Task WriteAsync(string? value) =>
        value is null ? Task.CompletedTask : inner.WriteAsync(redactor.Redact(value));

    public override Task WriteAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default) =>
        inner.WriteAsync(redactor.Redact(new string(buffer.Span)).AsMemory(), cancellationToken);

    public override Task WriteLineAsync(string? value) =>
        inner.WriteLineAsync(value is null ? null : redactor.Redact(value));

    public override Task WriteLineAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default) =>
        inner.WriteLineAsync(redactor.Redact(new string(buffer.Span)).AsMemory(), cancellationToken);

    public override void Flush() => inner.Flush();

    public override Task FlushAsync() => inner.FlushAsync();

    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

    /// <summary>
    /// Points Console.Error (and Console.Out when <paramref name="includeStdout"/> is true) at a redacting
    /// writer. In stdio mode stdout carries the MCP protocol and is left alone. Call it once, at start-up,
    /// before anything is logged and before the host (and its console logger) is built.
    /// </summary>
    public static void InstallOnConsole(SecretRedactor redactor, bool includeStdout)
    {
        if (includeStdout)
        {
            Console.SetOut(new RedactingTextWriter(Console.Out, redactor));
        }

        Console.SetError(new RedactingTextWriter(Console.Error, redactor));
    }
}
