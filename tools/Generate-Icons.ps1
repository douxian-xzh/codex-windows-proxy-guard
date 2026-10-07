param([string]$OutputDirectory = "$PSScriptRoot\..\src\CodexProxyManager\Assets")
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationCore, WindowsBase
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
function Brush([string]$color) { return [Windows.Media.BrushConverter]::new().ConvertFromString($color) }
function Render-Icon([int]$size, [bool]$tray) {
    $visual = [Windows.Media.DrawingVisual]::new()
    $dc = $visual.RenderOpen()
    $dc.PushTransform([Windows.Media.ScaleTransform]::new($size / 256.0, $size / 256.0))
    $background = [Windows.Media.LinearGradientBrush]::new((Brush '#172D3B').Color, (Brush '#091A26').Color, 55)
    $dc.DrawRoundedRectangle($background, $null, [Windows.Rect]::new(4,4,248,248), 58,58)
    $mint = Brush '#54E0BB'
    $pen = [Windows.Media.Pen]::new($mint, 20)
    $pen.StartLineCap = 'Round'; $pen.EndLineCap = 'Round'; $pen.LineJoin = 'Round'
    $dc.DrawGeometry($null, $pen, [Windows.Media.Geometry]::Parse('M 167 72 L 102 72 C 67 72 56 94 56 128 C 56 163 70 184 103 184 L 137 184'))
    $dc.DrawGeometry($null, $pen, [Windows.Media.Geometry]::Parse('M 108 128 L 202 128 M 178 104 L 202 128 L 178 152'))
    $dc.DrawEllipse((Brush '#E7FFF8'), $null, [Windows.Point]::new(170,72), 13,13)
    if (!$tray) { $dc.DrawEllipse($mint, $null, [Windows.Point]::new(141,184), 11,11) }
    $dc.Pop(); $dc.Close()
    $bitmap = [Windows.Media.Imaging.RenderTargetBitmap]::new($size,$size,96,96,[Windows.Media.PixelFormats]::Pbgra32)
    $bitmap.Render($visual)
    $encoder = [Windows.Media.Imaging.PngBitmapEncoder]::new()
    $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
    $stream = [IO.MemoryStream]::new(); $encoder.Save($stream)
    $bytes = $stream.ToArray(); $stream.Dispose()
    return ,$bytes
}
function Write-Icon([string]$name, [int[]]$sizes, [bool]$tray) {
    $images = @($sizes | ForEach-Object { ,(Render-Icon $_ $tray) })
    $stream = [IO.File]::Create((Join-Path $OutputDirectory "$name.ico"))
    $writer = [IO.BinaryWriter]::new($stream)
    try {
        $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$sizes.Count)
        $offset = 6 + 16 * $sizes.Count
        for ($i=0; $i -lt $sizes.Count; $i++) {
            $dimension = if ($sizes[$i] -eq 256) { 0 } else { $sizes[$i] }
            $writer.Write([byte]$dimension); $writer.Write([byte]$dimension)
            $writer.Write([byte]0); $writer.Write([byte]0)
            $writer.Write([uint16]1); $writer.Write([uint16]32)
            $writer.Write([uint32]$images[$i].Length); $writer.Write([uint32]$offset)
            $offset += $images[$i].Length
        }
        foreach ($bytes in $images) { $writer.Write([byte[]]$bytes) }
    } finally { $writer.Dispose() }
    [IO.File]::WriteAllBytes((Join-Path $OutputDirectory "$name.png"), (Render-Icon 256 $tray))
}
Write-Icon 'App' @(16,20,24,32,40,48,64,128,256) $false
Write-Icon 'Tray' @(16,20,24,32,48) $true
