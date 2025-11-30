@echo off
cd /d "%~dp0"

if exist "%USERPROFILE%\ZAP\.ZAP_JVM.properties" (
    set /p jvmopts=< "%USERPROFILE%\ZAP\.ZAP_JVM.properties"
) else (
    set jvmopts=-Xmx2G
)

REM Gunakan home directory khusus agar tidak konflik dengan ZAP lain
java %jvmopts% -jar zap-2.16.1.jar -dir "%~dp0\home" %*
