@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Neutron Tam Kaldirma

fltmc.exe >nul 2>&1
if not "%errorlevel%"=="0" (
  echo [HATA] Bu dosyayi yonetici olarak calistirman gerekiyor.
  echo Dosyaya sag tikla ve "Yonetici olarak calistir" sec.
  pause
  exit /b 5
)

set "STATE_FILE=%~dp0neutron-remove-root.txt"
set "INSTALL_ROOT="
set "PREVIOUSLY_VALIDATED=0"

if exist "%STATE_FILE%" (
  for /f "usebackq tokens=1,* delims==" %%A in ("%STATE_FILE%") do if /i "%%A"=="INSTALL_ROOT" set "INSTALL_ROOT=%%B"
  set "PREVIOUSLY_VALIDATED=1"
)

if not defined INSTALL_ROOT (
  for /f "tokens=2,*" %%A in ('reg.exe query "HKLM\SOFTWARE\Neutron" /v InstallLocation /reg:64 2^>nul ^| findstr.exe /i "InstallLocation"') do set "INSTALL_ROOT=%%B"
)
if not defined INSTALL_ROOT set "INSTALL_ROOT=%ProgramFiles%\Neutron"

if /i "%INSTALL_ROOT%"=="%SystemDrive%\" goto unsafe_path
if /i "%INSTALL_ROOT%"=="%SystemRoot%" goto unsafe_path
if /i "%INSTALL_ROOT%"=="%ProgramFiles%" goto unsafe_path
if defined ProgramFiles(x86) if /i "%INSTALL_ROOT%"=="%ProgramFiles(x86)%" goto unsafe_path

if "%PREVIOUSLY_VALIDATED%"=="0" (
  if not exist "%INSTALL_ROOT%\Uninstall.exe" goto missing_markers
  if not exist "%INSTALL_ROOT%\Neutron.exe" if not exist "%INSTALL_ROOT%\resources\app\src\main.cjs" goto missing_markers
  set INSTALL_ROOT>"%STATE_FILE%"
)

echo Kurulum yolu dogrulandi:
set INSTALL_ROOT
echo.

REM Nothing below can delete a file that is still open. The desktop app and
REM the LocalSystem service both run out of INSTALL_ROOT, so without this the
REM script always ended at "reboot required" on a machine where Neutron was
REM simply running.
echo Calisan Neutron surecleri durduruluyor...
taskkill.exe /F /T /IM Neutron.exe >nul 2>&1
taskkill.exe /F /T /IM NeutronServiceHost.exe >nul 2>&1
taskkill.exe /F /T /IM neutron-engine.exe >nul 2>&1
sc.exe stop NeutronService >nul 2>&1
REM sc stop only submits the request; give the SCM time to release the image.
ping.exe -n 5 127.0.0.1 >nul 2>&1

echo Neutron AMSI kayitlari temizleniyor...
reg.exe delete "HKLM\SOFTWARE\Microsoft\AMSI\Providers\{ADACFA90-B877-414D-A818-2EA5291E290E}" /f /reg:64 >nul 2>&1
reg.exe delete "HKLM\SOFTWARE\Classes\CLSID\{ADACFA90-B877-414D-A818-2EA5291E290E}" /f /reg:64 >nul 2>&1
reg.exe delete "HKLM\SOFTWARE\Microsoft\AMSI\Providers\{ADACFA90-B877-414D-A818-2EA5291E290E}" /f /reg:32 >nul 2>&1
reg.exe delete "HKLM\SOFTWARE\Classes\CLSID\{ADACFA90-B877-414D-A818-2EA5291E290E}" /f /reg:32 >nul 2>&1

echo Neutron baslangic bilesenleri kaldiriliyor...
sc.exe config NeutronService start= disabled >nul 2>&1
sc.exe delete NeutronService >nul 2>&1
schtasks.exe /change /tn NeutronWatchdog /disable >nul 2>&1
schtasks.exe /delete /tn NeutronWatchdog /f >nul 2>&1

echo Neutron program kayitlari kaldiriliyor...
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Neutron" /f /reg:64 >nul 2>&1
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Neutron" /f /reg:32 >nul 2>&1
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Neutron.exe" /f /reg:64 >nul 2>&1
reg.exe delete "HKLM\SOFTWARE\Neutron" /f /reg:64 >nul 2>&1
del /f /q "%PUBLIC%\Desktop\Neutron.lnk" >nul 2>&1
del /f /q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Neutron.lnk" >nul 2>&1

echo Neutron guvenlik duvari kurallari kaldiriliyor...
netsh.exe advfirewall firewall delete rule name=all program="%INSTALL_ROOT%\Neutron.exe" >nul 2>&1
REM Named Neutron-FW-* rules and the obsolete Security Center registration
REM are not reachable through netsh alone. Same encoded payload the
REM uninstaller runs, so the two cleanup paths cannot drift apart.
powershell.exe -NoProfile -NonInteractive -EncodedCommand JABFAHIAcgBvAHIAQQBjAHQAaQBvAG4AUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwA7ACAARwBlAHQALQBDAGkAbQBJAG4AcwB0AGEAbgBjAGUAIAAtAE4AYQBtAGUAcwBwAGEAYwBlACAAcgBvAG8AdABcAFMAZQBjAHUAcgBpAHQAeQBDAGUAbgB0AGUAcgAyACAALQBDAGwAYQBzAHMATgBhAG0AZQAgAEEAbgB0AGkAVgBpAHIAdQBzAFAAcgBvAGQAdQBjAHQAIAAtAEYAaQBsAHQAZQByACAAIgBpAG4AcwB0AGEAbgBjAGUARwB1AGkAZAA9ACcAYQBjADAAMAAwADgAYgAwAC0ANQA2ADQAYQAtADQANABmADgALQA4AGUAYwA3AC0AZgAyAGEAMgBkADgAMgBhADgAZgBlADgAJwAiACAAfAAgAFIAZQBtAG8AdgBlAC0AQwBpAG0ASQBuAHMAdABhAG4AYwBlADsAIABHAGUAdAAtAE4AZQB0AEYAaQByAGUAdwBhAGwAbABSAHUAbABlACAALQBOAGEAbQBlACAAJwBOAGUAdQB0AHIAbwBuAC0ARgBXAC0AKgAnACAAfAAgAFIAZQBtAG8AdgBlAC0ATgBlAHQARgBpAHIAZQB3AGEAbABsAFIAdQBsAGUA >nul 2>&1

echo Neutron Baslat menusu klasoru kaldiriliyor...
rd /s /q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Neutron" >nul 2>&1

echo Neutron program dosyalari siliniyor...
rd /s /q "%INSTALL_ROOT%" >nul 2>&1
if exist "%INSTALL_ROOT%" goto reboot_required

REM %ProgramData%\Neutron holds the licence, the settings database and the
REM quarantine. Quarantined files are the user's own files that Neutron moved
REM aside, and deleting them is irreversible -- so this is asked, never
REM assumed. Leaving it behind is harmless: a fresh install reuses it.
echo.
echo Geriye Neutron verileri kaldi:
echo   "%ProgramData%\Neutron"            (lisans, ayarlar, servis veritabani, KARANTINA)
echo   "%%USERPROFILE%%\AppData\Roaming\Neutron"  (her kullanici icin: ML modelleri ~500 MB, veritabani, KARANTINA)
echo.
echo Karantinadaki dosyalar senin kendi dosyalarindir; silinirse geri gelmez.
echo Silmezsen bu veriler diskte kalir ve Neutron'u yeniden kurarsan kullanilir.
echo.
set "PURGE_DATA="
set /p "PURGE_DATA=Bu veriler de silinsin mi? (E = evet, baska tus = hayir): "
REM The per-profile loop below is deliberate: the elevated console's own
REM AppData belongs to whoever approved the UAC prompt, which is not
REM necessarily the account that installed and used Neutron. Comments stay
REM outside the parenthesised block -- REM inside one is a known way to
REM break cmd parsing.
if /i "%PURGE_DATA%"=="E" (
  rd /s /q "%ProgramData%\Neutron" >nul 2>&1
  for /d %%P in ("%SystemDrive%\Users\*") do rd /s /q "%%~fP\AppData\Roaming\Neutron" >nul 2>&1
  if exist "%ProgramData%\Neutron" (
    echo [UYARI] Klasor tamamen silinemedi, bazi dosyalar kilitli olabilir.
  ) else (
    echo Veriler silindi.
  )
) else (
  echo Veriler birakildi.
)

del /f /q "%STATE_FILE%" >nul 2>&1
echo.
echo [BASARILI] Neutron programi ve baslangic kayitlari kaldirildi.
echo Bilgisayari bir kez yeniden baslat.
pause
exit /b 0

:reboot_required
echo.
echo [YENIDEN BASLAT] Neutron kayitlari temizlendi ancak calisan dosyalar kilitli.
echo Bilgisayari yeniden baslat ve bu CMD dosyasini tekrar yonetici olarak calistir.
echo Eski Uninstall.exe dosyasini calistirma.
pause
exit /b 10

:missing_markers
echo.
echo [HATA] Guvenlik icin klasor silinmedi. Neutron isaretleri bulunamadi:
set INSTALL_ROOT
echo Bu pencerenin fotografini gonder.
pause
exit /b 2

:unsafe_path
echo.
echo [HATA] Guvenli olmayan klasor yolu reddedildi:
set INSTALL_ROOT
echo Bu pencerenin fotografini gonder.
pause
exit /b 3
