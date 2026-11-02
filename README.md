# Scam Shield

Scam Shield is a Flask web app for checking suspicious website URLs, email addresses, and internship certificate IDs. It provides explainable risk indicators based on local rules, certificate records, and reports saved in the app's SQLite database.

> **Important:** Scam Shield is an initial screening aid, not proof that something is safe or fraudulent. A low-risk result does not guarantee legitimacy. Verify independently with the organization using contact details from its official website.

## Features

- Check URLs for warning signs such as HTTP connections, numeric IP addresses, shortened links, unusual domains, and flagged keywords.
- Review email addresses for format issues and signals such as disposable or free email providers.
- Check internship certificate IDs against locally stored certificate records. You can also upload a certificate image for in-browser text recognition and review the extracted text before scanning.
- See a risk score, verdict, and explanations for findings.
- Save check history and submit or review community reports.
- View dashboard statistics and recent activity.

Checks use local heuristics and data saved in this app; they do not query an external threat-intelligence service. Scores are indicators and can produce false positives or miss scams.

## Requirements

- Python 3
- Flask
- An internet connection to load the browser-based OCR library and English language data when scanning certificate images

## Run locally

From the project directory, create and activate a virtual environment, install Flask, and start the app:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install Flask
python app.py
```

Then open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

The app creates `database.db` in the project directory on startup. It stores check history and reports locally; it is not associated with individual user accounts.

Source files use UTF-8, and the VS Code workspace is configured to open text files with that encoding. `database.db` is a binary SQLite database, not a text or source-code file; inspect it with a SQLite viewer or through the app rather than opening it as text.

## Keep the local website running on Windows

To start Scam Shield automatically when you sign in to Windows and open it in your browser, run this once from PowerShell in the project directory:

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PWD\start_scam_shield.ps1`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName "Scam Shield Local Website" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force
Start-ScheduledTask -TaskName "Scam Shield Local Website"
```

The background task restarts the local app if it stops. Server logs are saved under `%LOCALAPPDATA%\ScamShield\logs`. The `127.0.0.1` address is private to this computer; the site is unavailable while the computer is off or asleep and is not public internet hosting.

## Privacy notes

- Certificate images are processed in the browser and are not uploaded. Recognized text is sent to the local app for analysis.
- OCR loads Tesseract.js and its English language data from the internet. You can enter a certificate ID manually instead.
- Do not submit passwords, one-time codes, banking details, or other sensitive personal information.

## Project structure

```text
app.py                 Flask app, local SQLite storage, and checking logic
start_scam_shield.ps1  Windows local server and browser auto-start
static/
  script.js            Browser interactions and certificate-image OCR
  style.css            App styles
templates/             Flask HTML templates
```
