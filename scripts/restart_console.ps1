# MCP Shield · 一键重启可视化控制台（演示用）
#
# 为什么需要它：
#   控制台脚本是「改了代码」之后才带上目录监听的。
#   如果旧进程还在后台占着 8787 端口，你再敲一次启动命令会**报端口占用**，
#   于是你看到的还是旧页面（灰角标、"数据生成"时间是旧的）。
#   这个脚本会自动把占着端口的旧进程结束掉，再启动一份新的。
#
# 用法（在项目根目录下）：
#   .\scripts\restart_console.ps1
#   .\scripts\restart_console.ps1 -CheckOnly     # 只看状态，不动任何进程
#   .\scripts\restart_console.ps1 -Interval 0.5  # 监听更灵敏（默认 1 秒）

param(
    [int]$Port = 8787,
    [double]$Interval = 1.0,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

function Find-PortOwners([int]$p) {
    try {
        Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction Stop |
            Select-Object -ExpandProperty OwningProcess -Unique
    } catch {
        @()
    }
}

function Show-State([int]$p) {
    $owners = @(Find-PortOwners $p)
    if ($owners.Count -eq 0) {
        Write-Host "  端口 $p ：没有进程在监听（控制台没在运行）" -ForegroundColor Yellow
        return
    }
    foreach ($pid_ in $owners) {
        $proc = Get-Process -Id $pid_ -ErrorAction SilentlyContinue
        $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$pid_" -ErrorAction SilentlyContinue).CommandLine
        Write-Host "  端口 $p ：PID $pid_  $($proc.ProcessName)  启动于 $($proc.StartTime)" -ForegroundColor Gray
        Write-Host "               $cmd" -ForegroundColor DarkGray
    }
    $watchOk = $false
    try {
        $w = Invoke-RestMethod "http://127.0.0.1:$p/api/watch" -TimeoutSec 4
        $watchOk = $true
        Write-Host "  /api/watch ：可用，enabled=$($w.enabled)  scan_count=$($w.scan_count)  间隔=$($w.interval)s" -ForegroundColor Green
    } catch {
        Write-Host "  /api/watch ：不可用（404 / 连不上）" -ForegroundColor Red
    }
    try {
        $s = Invoke-RestMethod "http://127.0.0.1:$p/api/snapshot" -TimeoutSec 6
        Write-Host "  数据生成时间：$($s.generated_at)" -ForegroundColor Gray
    } catch { }
    if (-not $watchOk) {
        Write-Host ""
        Write-Host "  >>> 上面这个（些）进程跑的是**改动前**的旧代码，右上角不会有绿色监听角标。" -ForegroundColor Yellow
        Write-Host "  >>> 重新执行一次本脚本（去掉 -CheckOnly）即可自动结束旧的、启动新的。" -ForegroundColor Yellow
    }
}

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " MCP Shield -- 可视化控制台 重启助手" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "当前状态：" -ForegroundColor White
Show-State $Port
Write-Host ""

if ($CheckOnly) { exit 0 }

# 结束占用端口的旧进程（只结束跑 ui_server.py 的 python，避免误杀别的程序）
$owners = @(Find-PortOwners $Port)
foreach ($pid_ in $owners) {
    $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$pid_" -ErrorAction SilentlyContinue).CommandLine
    if (-not $cmd -or $cmd -notmatch 'ui_server') {
        Write-Host "跳过 PID $pid_（命令行里没有 ui_server）：$cmd" -ForegroundColor Yellow
        continue
    }
    Write-Host "正在结束旧进程 PID $pid_ ..." -ForegroundColor Yellow
    try { Stop-Process -Id $pid_ -Force -ErrorAction Stop; Write-Host "  已结束。" -ForegroundColor Green }
    catch { Write-Host "  结束失败：$($_.Exception.Message)" -ForegroundColor Red }
}
if ($owners.Count -gt 0) { Start-Sleep -Milliseconds 700 }

# 检查脚本在哪
$server = Join-Path (Get-Location).Path 'scripts\ui_server.py'
if (-not (Test-Path $server)) {
    Write-Host "找不到 $server" -ForegroundColor Red
    Write-Host "请先 cd 到项目根目录（能看到 mcp_shield.py 的那一层）再运行本脚本。" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "正在启动新的控制台（端口 $Port，监听间隔 ${Interval}s）..." -ForegroundColor Cyan
Write-Host "启动后请打开或强刷 http://127.0.0.1:$Port （Ctrl + F5）" -ForegroundColor Cyan
Write-Host "右上角应出现绿色角标： ● 目录监听中 · 每 ${Interval}s 自动重扫" -ForegroundColor Green
Write-Host ""
Write-Host ">> 这个窗口现在是服务器窗口，演示期间不要关、不要按 Ctrl+C。" -ForegroundColor Yellow
Write-Host ""

& python scripts\ui_server.py --port $Port --open --watch-interval $Interval
