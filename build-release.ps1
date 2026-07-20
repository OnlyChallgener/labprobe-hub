param(
    [Parameter(Mandatory = $true)]
    [string]$AppVersion,

    [Parameter(Mandatory = $true)]
    [int]$AppBuild,

    [Parameter(Mandatory = $true)]
    [string]$AgentVersion,

    [string]$AppChangelog = "功能优化与问题修复。",
    [string]$AgentChangelog = "Agent 功能优化与问题修复。",

    [string]$Repo = "D:\Github\labprobe-hub",
    [string]$Release = "D:\Release",
    [string]$RootUrl = "https://lab.net86.dynv6.net:27772"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# 输入文件
$AppSource       = Join-Path $Release "app-release.apk"
$AgentSource     = Join-Path $Release "labrelay-linux-arm64"
$InstallerSource = Join-Path $Repo "scripts\labprobe-install.sh"

# 输出目录
$Output   = Join-Path $Release "update-bundle"
$AppDir   = Join-Path $Output "app"
$AgentDir = Join-Path $Output "agent"

# 检查输入文件
foreach ($File in @($AppSource, $AgentSource, $InstallerSource)) {
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
        throw "缺少输入文件：$File"
    }
}

# 清理旧版更新包
if (Test-Path -LiteralPath $Output) {
    Remove-Item -LiteralPath $Output -Recurse -Force
}

New-Item -ItemType Directory -Path $AppDir, $AgentDir -Force | Out-Null

# 输出文件名
$ApkName      = "LabProbeApp-v$AppVersion.apk"
$AppDest      = Join-Path $AppDir $ApkName
$AgentDest    = Join-Path $AgentDir "labrelay-linux-arm64"
$InstallerDest = Join-Path $AgentDir "install.sh"

Copy-Item -LiteralPath $AppSource -Destination $AppDest
Copy-Item -LiteralPath $AgentSource -Destination $AgentDest

# install.sh 转为 Linux LF 换行并使用 UTF-8 无 BOM
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$InstallerText = [System.IO.File]::ReadAllText($InstallerSource)
$InstallerText = $InstallerText.Replace("`r`n", "`n").Replace("`r", "`n")
[System.IO.File]::WriteAllText($InstallerDest, $InstallerText, $Utf8NoBom)

function Get-ArtifactInfo {
    param(
        [string]$Path,
        [string]$Url,
        [string]$FallbackUrl
    )

    return [ordered]@{
        url         = $Url
        fallbackUrl = $FallbackUrl
        sha256      = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        sizeBytes   = [int64](Get-Item -LiteralPath $Path).Length
    }
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$Data
    )

    $Json = $Data | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($Path, $Json + "`n", $Utf8NoBom)
}

# APP 更新信息
$AppMeta = Get-ArtifactInfo `
    -Path $AppDest `
    -Url "$RootUrl/app/$ApkName" `
    -FallbackUrl "https://github.com/OnlyChallgener/LabProbeApp/releases/latest/download/$ApkName"

$AppJson = [ordered]@{
    schemaVersion = 1
    versionCode   = $AppBuild
    versionName   = $AppVersion
    forceUpdate   = $false
    downloadUrl   = $AppMeta.url
    fallbackUrl   = $AppMeta.fallbackUrl
    sha256        = $AppMeta.sha256
    sizeBytes     = $AppMeta.sizeBytes
    changelog     = $AppChangelog
}

Write-JsonFile `
    -Path (Join-Path $AppDir "update.json") `
    -Data $AppJson

# Agent 更新信息
$AgentMeta = Get-ArtifactInfo `
    -Path $AgentDest `
    -Url "$RootUrl/agent/labrelay-linux-arm64" `
    -FallbackUrl "https://github.com/OnlyChallgener/labprobe-hub/releases/latest/download/labrelay-linux-arm64"

$InstallerMeta = Get-ArtifactInfo `
    -Path $InstallerDest `
    -Url "$RootUrl/agent/install.sh" `
    -FallbackUrl "https://github.com/OnlyChallgener/labprobe-hub/releases/latest/download/labprobe-install.sh"

$AgentJson = [ordered]@{
    schemaVersion = 1
    versionName   = $AgentVersion
    changelog     = $AgentChangelog
    installUrl    = $InstallerMeta.url
    installer     = $InstallerMeta
    checksumsUrl  = "$RootUrl/agent/checksums.txt"
    binaries      = [ordered]@{
        arm64 = $AgentMeta
    }
}

Write-JsonFile `
    -Path (Join-Path $AgentDir "latest.json") `
    -Data $AgentJson

# checksums.txt
$Checksums = @(
    "$($AgentMeta.sha256)  labrelay-linux-arm64"
    "$($InstallerMeta.sha256)  install.sh"
) -join "`n"

[System.IO.File]::WriteAllText(
    (Join-Path $AgentDir "checksums.txt"),
    $Checksums + "`n",
    $Utf8NoBom
)

Write-Host ""
Write-Host "更新包生成成功" -ForegroundColor Green
Write-Host "APP：v$AppVersion build $AppBuild"
Write-Host "Agent：v$AgentVersion"
Write-Host "目录：$Output"
Write-Host ""

Get-ChildItem -LiteralPath $Output -Recurse -File |
    Select-Object FullName, Length |
    Format-Table -AutoSize

explorer.exe $Output