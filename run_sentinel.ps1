$env:GMAIL_AUTH_MODE = "oauth"
$env:GMAIL_MONITORED_MAILBOX = "you@example.com"

Set-Location "C:\Users\jacks\Documents\sentinel"
& "C:\Users\jacks\Documents\sentinel\venv\Scripts\sentinel-triage.exe" --once