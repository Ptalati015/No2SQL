namespace No2SQL.Hosting.OAuth;

/// <summary>
/// One JSON file of the data directory, cached in memory and shared with the <c>No2SQL oauth</c> commands
/// running as another process (threat model R23).
/// <list type="bullet">
/// <item><see cref="Read"/> compares the file's write time and length at most once per second and reloads a
/// changed file, so a revocation by the command line is seen within a second without a restart.</item>
/// <item><see cref="Update"/> takes the directory lock, always reloads a changed file first, changes it and
/// writes it atomically, so a change by one process is never overwritten with stale data by the other.</item>
/// </list>
/// </summary>
internal sealed class SharedDocument<T> where T : class, new()
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(1);

    private readonly OAuthDataDirectory _directory;
    private readonly string _name;
    private readonly TimeProvider _clock;
    private readonly Action<T>? _onLoaded;
    private readonly object _gate = new();

    private T _value;
    private (DateTime, long)? _stamp;
    private long _lastCheck;

    // Set while the file on disk cannot be read: every Read throws until a reload or an update succeeds.
    private OAuthDataException? _failure;

    /// <param name="onLoaded">Runs on every loaded or written value, under the lock, to rebuild indexes.</param>
    /// <exception cref="OAuthDataException">The file exists but cannot be read.</exception>
    public SharedDocument(OAuthDataDirectory directory, string name, TimeProvider clock, Action<T>? onLoaded = null)
    {
        _directory = directory;
        _name = name;
        _clock = clock;
        _onLoaded = onLoaded;
        _stamp = directory.Stamp(name);
        _value = directory.Read<T>(name) ?? new T();
        _onLoaded?.Invoke(_value);
        _lastCheck = clock.GetTimestamp();
    }

    /// <summary>The current value. Callers must not change it; use <see cref="Update"/>.</summary>
    public T Read()
    {
        var now = _clock.GetTimestamp();
        if (_clock.GetElapsedTime(Volatile.Read(ref _lastCheck), now) >= CheckInterval)
        {
            lock (_gate)
            {
                if (_clock.GetElapsedTime(_lastCheck, now) >= CheckInterval)
                {
                    _lastCheck = now;
                    ReloadIfChanged();
                }
            }
        }

        if (Volatile.Read(ref _failure) is { } failure)
        {
            throw failure;
        }

        return Volatile.Read(ref _value);
    }

    /// <summary>Changes the file under the directory lock. The change works on a fresh copy and is written atomically.</summary>
    /// <param name="change">Changes the copy and returns a result.</param>
    /// <param name="changed">Whether the result means the copy was changed and must be written; null means always.</param>
    public TResult Update<TResult>(Func<T, TResult> change, Func<TResult, bool>? changed = null) => _directory.WithLock(() =>
    {
        lock (_gate)
        {
            // Work on a copy read from disk, so a failed change leaves the cached value untouched.
            var working = _directory.Read<T>(_name) ?? new T();
            var result = change(working);
            if (changed is null || changed(result))
            {
                _directory.Write(_name, working);
                _lastCheck = _clock.GetTimestamp();
            }

            _onLoaded?.Invoke(working);
            Volatile.Write(ref _value, working);
            Volatile.Write(ref _failure, null);
            _stamp = _directory.Stamp(_name);
            return result;
        }
    });

    private void ReloadIfChanged()
    {
        var stamp = _directory.Stamp(_name);
        if (stamp == _stamp && _failure is null)
        {
            return;
        }

        // A file that cannot be read fails closed: this and every later Read throws (a token check then
        // answers 401) until the file can be read again. The cached value is not used in between.
        try
        {
            var value = _directory.Read<T>(_name) ?? new T();
            _onLoaded?.Invoke(value);
            Volatile.Write(ref _value, value);
            Volatile.Write(ref _failure, null);
            _stamp = stamp;
        }
        catch (OAuthDataException ex)
        {
            Volatile.Write(ref _failure, ex);
            throw;
        }
    }
}
