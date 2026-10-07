using System.IO;
using System.Text.Json;

namespace CodexProxyManager.Services;

public sealed class AppearancePreferences
{
    public bool DarkTheme { get; set; }
    public int LayoutVersion { get; set; }
    public Dictionary<string, bool> Sections { get; set; } = [];
}

public static class AppearanceStore
{
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "CodexProxyManagerPywBranch", "appearance.json");

    public static AppearancePreferences Load()
    {
        try
        {
            var preferences = JsonSerializer.Deserialize<AppearancePreferences>(File.ReadAllText(FilePath)) ?? new();
            preferences.Sections ??= [];
            return preferences;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return new();
        }
    }

    public static void Save(AppearancePreferences preferences)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var temporaryPath = FilePath + ".tmp";
        File.WriteAllText(temporaryPath, JsonSerializer.Serialize(preferences, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temporaryPath, FilePath, overwrite: true);
    }
}
