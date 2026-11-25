using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>
/// The clock comes from DI. Rules that depend on time (token lifetimes, rate limits, timeouts) take
/// <see cref="TimeProvider"/> from the container, and their tests replace it as shown here.
/// </summary>
public class TimeProviderTests
{
    [Fact]
    public void The_system_clock_is_registered_by_default()
    {
        using var app = new No2SqlHttpApp();

        Assert.Same(TimeProvider.System, app.Services.GetRequiredService<TimeProvider>());
    }

    [Fact]
    public void A_test_can_replace_the_clock_and_move_it()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using var app = new No2SqlHttpApp(services => services.AddSingleton<TimeProvider>(clock));

        var resolved = app.Services.GetRequiredService<TimeProvider>();
        clock.Advance(TimeSpan.FromHours(1));

        Assert.Same(clock, resolved);
        Assert.Equal(new DateTimeOffset(2026, 1, 1, 1, 0, 0, TimeSpan.Zero), resolved.GetUtcNow());
    }
}
