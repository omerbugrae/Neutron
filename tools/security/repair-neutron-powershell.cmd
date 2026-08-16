@echo off
setlocal EnableExtensions
title Neutron AMSI Acil Onarim

fltmc >nul 2>&1
if not "%errorlevel%"=="0" (
  echo [HATA] Bu dosyayi yonetici olarak calistirman gerekiyor.
  echo Dosyaya sag tiklayip "Yonetici olarak calistir" sec.
  pause
  exit /b 5
)

echo Yalniz Neutron AMSI kayitlari temizleniyor...
reg.exe delete "HKLM\SOFTWARE\Microsoft\AMSI\Providers\{ADACFA90-B877-414D-A818-2EA5291E290E}" /f /reg:64 >nul 2>&1
reg.exe delete "HKLM\SOFTWARE\Classes\CLSID\{ADACFA90-B877-414D-A818-2EA5291E290E}" /f /reg:64 >nul 2>&1
reg.exe delete "HKLM\SOFTWARE\Microsoft\AMSI\Providers\{ADACFA90-B877-414D-A818-2EA5291E290E}" /f /reg:32 >nul 2>&1
reg.exe delete "HKLM\SOFTWARE\Classes\CLSID\{ADACFA90-B877-414D-A818-2EA5291E290E}" /f /reg:32 >nul 2>&1

echo Neutron baslangic bilesenleri devre disi birakiliyor...
sc.exe config NeutronService start= disabled >nul 2>&1
sc.exe delete NeutronService >nul 2>&1
schtasks.exe /change /tn NeutronWatchdog /disable >nul 2>&1
schtasks.exe /delete /tn NeutronWatchdog /f >nul 2>&1

reg.exe query "HKLM\SOFTWARE\Microsoft\AMSI\Providers\{ADACFA90-B877-414D-A818-2EA5291E290E}" /reg:64 >nul 2>&1
if "%errorlevel%"=="0" goto cleanup_failed
reg.exe query "HKLM\SOFTWARE\Classes\CLSID\{ADACFA90-B877-414D-A818-2EA5291E290E}" /reg:64 >nul 2>&1
if "%errorlevel%"=="0" goto cleanup_failed
reg.exe query "HKLM\SOFTWARE\Microsoft\AMSI\Providers\{ADACFA90-B877-414D-A818-2EA5291E290E}" /reg:32 >nul 2>&1
if "%errorlevel%"=="0" goto cleanup_failed
reg.exe query "HKLM\SOFTWARE\Classes\CLSID\{ADACFA90-B877-414D-A818-2EA5291E290E}" /reg:32 >nul 2>&1
if "%errorlevel%"=="0" goto cleanup_failed

echo.
echo [BASARILI] Neutron AMSI kayitlari temizlendi.
echo Simdi bilgisayari yeniden baslat. Yeniden baslatmadan PowerShell acma.
pause
exit /b 0

:cleanup_failed
echo.
echo [HATA] Neutron AMSI kayitlarindan biri silinemedi.
echo Bu pencerenin fotografini gonder; program klasorunu elle silme.
pause
exit /b 1
