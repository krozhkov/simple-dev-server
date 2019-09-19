@echo off
rem  --> check for permissions
if "%PROCESSOR_ARCHITECTURE%" equ "amd64" (
    >nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) else (
    >nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

rem --> if error flag set, we do not have admin.
if %ERRORLEVEL% neq 0 (
    echo Run script as administrator...
    exit /b 1
) else (
    goto runAsAdmin
)

:runAsAdmin
openssl req -x509 -out localhost.crt -keyout localhost.key -days 3650 -newkey rsa:2048 -nodes -sha256 -subj '/CN=localhost' -extensions EXT -config openssl.conf
certutil -addstore Root localhost.crt
