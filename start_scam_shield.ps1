$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$python = @(
  (Join-Path $projectRoot ".venv\Scripts\python.exe"),
  (Join-Path $projectRoot "venv\Scripts\python.exe")
) | Where-Object { Test-Path $_ } | Select-Object -First 1
$url = "http://127.0.0.1:5000/"
$logDirectory = Join-Path $env:LOCALAPPDATA "ScamShield\logs"
$stdoutLog = Join-Path $logDirectory "server.log"
$stderrLog = Join-Path $logDirectory "server-error.log"

if (-not $python) {
  throw "Scam Shield Python environment not found. Create .venv or venv before starting the website."
}

New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$browserOpened = $false
$serverProcess = $null

while ($true) {
  $isHealthy = $false
  try {
    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
    $isHealthy = $response.StatusCode -eq 200
  }
  catch {
    $isHealthy = $false
  }

  if ($isHealthy) {
    if (-not $browserOpened) {
      Start-Process $url
      $browserOpened = $true
    }
  }
  elseif ($null -eq $serverProcess -or $serverProcess.HasExited) {
    foreach ($log in @($stdoutLog, $stderrLog)) {
      if ((Test-Path $log) -and (Get-Item $log).Length -gt 5MB) {
        Move-Item -Path $log -Destination "$log.previous" -Force
      }
    }

    $serverProcess = Start-Process `
      -FilePath $python `
      -ArgumentList "app.py" `
      -WorkingDirectory $projectRoot `
      -WindowStyle Hidden `
      -RedirectStandardOutput $stdoutLog `
      -RedirectStandardError $stderrLog `
      -PassThru
  }

  Start-Sleep -Seconds 5
}
