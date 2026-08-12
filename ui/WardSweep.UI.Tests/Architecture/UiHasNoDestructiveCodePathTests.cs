using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using WardSweep.UI.ViewModels;

namespace WardSweep.UI.Tests.Architecture;

/// <summary>
/// Enforces the guarantee in docs/09-UI-SPEC.md: "the UI process has no
/// destructive code path at all".
/// </summary>
/// <remarks>
/// <para>
/// These are the tests <c>.github/workflows/dotnet-ci.yml</c> runs as the
/// <c>arch-tests</c> job (<c>test-filter: 'Category=Architecture'</c>). The
/// guarantee is worth something only if it cannot quietly lapse, and review is
/// not a mechanism.
/// </para>
/// <para>
/// The check reads the assembly's TypeReference table directly with
/// <see cref="MetadataReader"/> rather than through reflection. That table lists
/// every external type the assembly mentions anywhere, including from inside
/// method bodies — which is exactly where a stray <c>File.Delete</c> would hide
/// and where reflection cannot see. It needs no third-party package.
/// </para>
/// <para>
/// Known limitation: the table is assembly-wide, so a violation is reported
/// without naming the type that caused it. That is the right trade while the UI
/// is small; the assembly-wide ban is a stronger claim than the per-type one,
/// not a weaker substitute for it.
/// </para>
/// </remarks>
public sealed class UiHasNoDestructiveCodePathTests
{
    /// <summary>
    /// Registry types the UI may never reference.
    /// </summary>
    /// <remarks>
    /// Scoped to the registry types by name, not to the whole
    /// <c>Microsoft.Win32</c> namespace: <c>OpenFileDialog</c>,
    /// <c>SaveFileDialog</c> and <c>SystemEvents</c> live there too and are
    /// perfectly ordinary things for a WPF app to use.
    /// </remarks>
    private static readonly string[] ForbiddenRegistryTypes =
    [
        "Registry",
        "RegistryKey",
        "RegistryHive",
        "RegistryView",
        "RegistryValueKind",
        "RegistryOptions",
    ];

    /// <summary>
    /// Filesystem types that can destroy something.
    /// </summary>
    /// <remarks>
    /// <c>Path</c> and the stream types are not here: composing a path or
    /// reading a file is not a destructive code path, and banning them would
    /// make the rule so inconvenient that someone would eventually delete it.
    /// </remarks>
    private static readonly string[] ForbiddenFileSystemTypes =
    [
        "File",
        "Directory",
        "FileInfo",
        "DirectoryInfo",
        "FileSystemInfo",
    ];

    private static List<(string Namespace, string Name)> TypeReferences()
    {
        var location = typeof(MainWindowViewModel).Assembly.Location;
        Assert.False(
            string.IsNullOrEmpty(location),
            "the UI assembly must be on disk for its metadata to be read");

        using var stream = System.IO.File.OpenRead(location);
        using var peReader = new PEReader(stream);
        var metadata = peReader.GetMetadataReader();

        var references = new List<(string Namespace, string Name)>();
        foreach (var handle in metadata.TypeReferences)
        {
            var reference = metadata.GetTypeReference(handle);
            references.Add((
                metadata.GetString(reference.Namespace),
                metadata.GetString(reference.Name)));
        }

        return references;
    }

    [Fact]
    [Trait("Category", "Architecture")]
    public void UiAssemblyNeverReferencesTheRegistry()
    {
        var offenders = TypeReferences()
            .Where(reference =>
                reference.Namespace.StartsWith("Microsoft.Win32", StringComparison.Ordinal)
                && ForbiddenRegistryTypes.Contains(reference.Name, StringComparer.Ordinal))
            .Select(reference => $"{reference.Namespace}.{reference.Name}")
            .ToList();

        Assert.True(
            offenders.Count == 0,
            $"the UI must never touch the registry, but references: {string.Join(", ", offenders)}");
    }

    [Fact]
    [Trait("Category", "Architecture")]
    public void UiAssemblyNeverReferencesATypeThatCanDeleteFiles()
    {
        var offenders = TypeReferences()
            .Where(reference =>
                string.Equals(reference.Namespace, "System.IO", StringComparison.Ordinal)
                && ForbiddenFileSystemTypes.Contains(reference.Name, StringComparer.Ordinal))
            .Select(reference => $"{reference.Namespace}.{reference.Name}")
            .ToList();

        Assert.True(
            offenders.Count == 0,
            $"the UI must have no destructive filesystem path, but references: {string.Join(", ", offenders)}");
    }

    [Fact]
    [Trait("Category", "Architecture")]
    public void ViewModelsExposeNoFilesystemOrRegistryTypesInTheirSignatures()
    {
        var viewModels = typeof(MainWindowViewModel).Assembly
            .GetTypes()
            .Where(type => type.Namespace?.EndsWith(".ViewModels", StringComparison.Ordinal) == true)
            .ToList();

        Assert.NotEmpty(viewModels);

        var offenders = new List<string>();
        foreach (var type in viewModels)
        {
            const BindingFlags Flags =
                BindingFlags.Public | BindingFlags.NonPublic |
                BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

            var used = type.GetFields(Flags).Select(field => field.FieldType)
                .Concat(type.GetProperties(Flags).Select(property => property.PropertyType))
                .Concat(type.GetMethods(Flags).SelectMany(method =>
                    method.GetParameters().Select(parameter => parameter.ParameterType)
                        .Append(method.ReturnType)))
                .Concat(type.GetConstructors(Flags).SelectMany(constructor =>
                    constructor.GetParameters().Select(parameter => parameter.ParameterType)));

            offenders.AddRange(used
                .Where(IsForbidden)
                .Select(forbidden => $"{type.Name} -> {forbidden.FullName}"));
        }

        Assert.True(
            offenders.Count == 0,
            $"view models must not name filesystem or registry types: {string.Join(", ", offenders)}");
    }

    private static bool IsForbidden(Type type)
    {
        var candidate = type.IsByRef || type.IsArray || type.IsPointer
            ? type.GetElementType() ?? type
            : type;

        return candidate.Namespace switch
        {
            "System.IO" => true,
            not null when candidate.Namespace.StartsWith("Microsoft.Win32", StringComparison.Ordinal)
                => ForbiddenRegistryTypes.Contains(candidate.Name, StringComparer.Ordinal),
            _ => false,
        };
    }
}
