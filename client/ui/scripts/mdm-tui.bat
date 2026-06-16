@echo off
REM Double-click launcher for the NetBird MDM tester (Windows).
REM The .ps1 self-elevates.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0mdm-toggle.ps1"
