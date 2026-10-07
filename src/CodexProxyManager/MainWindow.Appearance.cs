using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using CodexProxyManager.Services;

namespace CodexProxyManager;

public partial class MainWindow
{
    private readonly AppearancePreferences _appearance = AppearanceStore.Load();

    private Expander[] Sections => [AdvancedSection, OverviewSection, ApplicationSection, ProxySection, ConnectionsSection, EventsSection];

    private void ApplyAppearance()
    {
        System.Windows.Application.Current.Resources.MergedDictionaries[0] = new ResourceDictionary
        {
            Source = new Uri($"Themes/{(_appearance.DarkTheme ? "Dark" : "Light")}.xaml", UriKind.Relative)
        };
        ThemeGlyphText.Text = _appearance.DarkTheme ? "\uE706" : "\uE708";
        ThemeButtonText.Text = _appearance.DarkTheme ? "浅色外观" : "深色外观";
        ApplyTitleBarTheme();
    }

    private void RestoreSections()
    {
        // Do not carry expanded launcher-era panels into the new compact home.
        // Preserve the user's theme and remember new layout choices after migration.
        if (_appearance.LayoutVersion < 2)
        {
            _appearance.Sections.Clear();
            _appearance.LayoutVersion = 2;
        }
        foreach (var section in Sections)
            if (_appearance.Sections.TryGetValue(section.Name, out var expanded))
                section.IsExpanded = expanded;
    }

    private void ThemeButton_Click(object sender, RoutedEventArgs e)
    {
        _appearance.DarkTheme = !_appearance.DarkTheme;
        ApplyAppearance();
        UpdateGuardianStatus();
        SaveAppearance();
    }

    private void SectionExpansionChanged(object sender, RoutedEventArgs e)
    {
        if (!_initialized || sender is not Expander section || !ReferenceEquals(e.OriginalSource, section)) return;
        _appearance.Sections[section.Name] = section.IsExpanded;
        SaveAppearance();
    }

    private void SaveAppearance()
    {
        try { AppearanceStore.Save(_appearance); }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
        { AddEvent("外观设置保存失败：" + ex.Message); }
    }

    private void ApplyTitleBarTheme()
    {
        var handle = new WindowInteropHelper(this).Handle;
        if (handle == IntPtr.Zero) return;
        var dark = _appearance.DarkTheme ? 1 : 0;
        _ = DwmSetWindowAttribute(handle, 20, ref dark, sizeof(int));
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

}
