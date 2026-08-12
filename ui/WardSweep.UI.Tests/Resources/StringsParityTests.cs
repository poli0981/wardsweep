using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace WardSweep.UI.Tests.Resources;

/// <summary>
/// The build enforcement docs/17-I18N.md asks for, on the C# side.
/// </summary>
/// <remarks>
/// docs/17 requires CI to fail on a key present in the source but missing from
/// a shipped locale, a key present in a locale but absent from the source, and
/// a placeholder mismatch between the two. Catching those here means a
/// translator's mistake shows up as a red test rather than as a crash in the
/// one string a Vietnamese user most needs to read.
/// </remarks>
public sealed class StringsParityTests
{
    private static readonly Regex Placeholder =
        new(@"\{(?<name>[A-Za-z_][A-Za-z0-9_]*)\}", RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    /// <summary>
    /// Locales that must be at parity with the source.
    /// </summary>
    /// <remarks>
    /// ja-JP is deliberately absent. docs/19-ROADMAP.md defers it to v1.x, and
    /// a Strings.ja.resx full of English would look finished while shipping a
    /// Japanese locale that is not Japanese.
    /// </remarks>
    public static TheoryData<string> ShippedLocales() => new() { "vi" };

    private static string ResourcesDirectory()
    {
        var directory = new System.IO.DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !System.IO.Directory.Exists(
                   System.IO.Path.Combine(directory.FullName, "ui", "WardSweep.UI", "Resources")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return System.IO.Path.Combine(directory!.FullName, "ui", "WardSweep.UI", "Resources");
    }

    private static Dictionary<string, string> Load(string fileName)
    {
        var path = System.IO.Path.Combine(ResourcesDirectory(), fileName);
        Assert.True(System.IO.File.Exists(path), $"{fileName} should exist at {path}");

        return XDocument.Load(path)
            .Root!
            .Elements("data")
            .ToDictionary(
                element => element.Attribute("name")!.Value,
                element => element.Element("value")?.Value ?? string.Empty,
                StringComparer.Ordinal);
    }

    [Theory]
    [MemberData(nameof(ShippedLocales))]
    public void EveryShippedLocaleHasExactlyTheSourceKeys(string locale)
    {
        var source = Load("Strings.resx");
        var translated = Load($"Strings.{locale}.resx");

        var missing = source.Keys.Except(translated.Keys, StringComparer.Ordinal).ToList();
        var extra = translated.Keys.Except(source.Keys, StringComparer.Ordinal).ToList();

        Assert.True(missing.Count == 0, $"{locale} is missing: {string.Join(", ", missing)}");
        Assert.True(extra.Count == 0, $"{locale} has keys the source does not: {string.Join(", ", extra)}");
    }

    [Theory]
    [MemberData(nameof(ShippedLocales))]
    public void PlaceholdersMatchBetweenSourceAndTranslation(string locale)
    {
        var source = Load("Strings.resx");
        var translated = Load($"Strings.{locale}.resx");

        foreach (var (key, sourceValue) in source)
        {
            if (!translated.TryGetValue(key, out var translatedValue))
            {
                continue; // reported by the key-parity test
            }

            var expected = Names(sourceValue);
            var actual = Names(translatedValue);

            Assert.True(
                expected.SetEquals(actual),
                $"{key} in {locale}: expected placeholders "
                    + $"[{string.Join(", ", expected.Order(StringComparer.Ordinal))}], "
                    + $"found [{string.Join(", ", actual.Order(StringComparer.Ordinal))}]");
        }
    }

    [Fact]
    public void KeysFollowTheAreaSubjectDetailConvention()
    {
        foreach (var key in Load("Strings.resx").Keys)
        {
            Assert.True(
                key.Split('.').Length >= 2,
                $"`{key}` should be <area>.<subject>[.<detail>] per docs/17-I18N.md");
            Assert.Equal(key.ToLowerInvariant(), key);
        }
    }

    private static HashSet<string> Names(string value) =>
        Placeholder.Matches(value)
            .Select(match => match.Groups["name"].Value)
            .ToHashSet(StringComparer.Ordinal);
}
