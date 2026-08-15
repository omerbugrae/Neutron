Unicode True

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"

!ifndef APP_DIR
  !error "APP_DIR is required"
!endif
!ifndef OUTPUT_FILE
  !error "OUTPUT_FILE is required"
!endif

Name "${APP_NAME}"
OutFile "${OUTPUT_FILE}"
!if "${TARGET_ARCH}" == "x64"
  InstallDir "$PROGRAMFILES64\\Neutron"
!else
  InstallDir "$PROGRAMFILES32\\Neutron"
!endif
InstallDirRegKey HKLM "Software\\Neutron" "InstallLocation"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
SetCompressorDictSize 64
CRCCheck on
ShowInstDetails nevershow
ShowUninstDetails nevershow
BrandingText "Neutron Security"

Var LicenseDialog
Var LicenseInput
Var LicenseDeviceInput
Var LicenseKey
Var LicenseDeviceHash
Var HadPreviousLicense
Var ProgramDataDir

VIProductVersion "${APP_VERSION}.0"
VIAddVersionKey /LANG=1055 "ProductName" "Neutron"
VIAddVersionKey /LANG=1055 "ProductVersion" "${APP_VERSION}"
VIAddVersionKey /LANG=1055 "FileVersion" "${APP_VERSION}"
VIAddVersionKey /LANG=1055 "CompanyName" "Neutron"
VIAddVersionKey /LANG=1055 "FileDescription" "Neutron Kurulum Sihirbazı"
VIAddVersionKey /LANG=1055 "LegalCopyright" "Neutron"

!define MUI_ICON "${PROJECT_ROOT}\\assets\\neutron.ico"
!define MUI_UNICON "${PROJECT_ROOT}\\assets\\neutron.ico"
!define MUI_ABORTWARNING
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "${PROJECT_ROOT}\\assets\\installer-banner.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "${PROJECT_ROOT}\\assets\\installer-dialog.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "${PROJECT_ROOT}\\assets\\installer-dialog.bmp"
!define MUI_BGCOLOR "FFFFFF"
!define MUI_TEXTCOLOR "18202B"
!define MUI_WELCOMEPAGE_TITLE "Neutron Kurulum Sihirbazına Hoş Geldiniz"
!define MUI_WELCOMEPAGE_TEXT "Bu sihirbaz Neutron güvenlik uygulamasını bilgisayarınıza kuracak.$\r$\n$\r$\nDevam etmeden önce diğer uygulamaları kapatmanız önerilir."
!define MUI_DIRECTORYPAGE_TEXT_TOP "Neutron'un kurulacağı klasörü seçin. Devam etmek için İleri'ye tıklayın."
!define MUI_FINISHPAGE_TITLE "Neutron Kurulumu Tamamlandı"
!define MUI_FINISHPAGE_TEXT "Neutron bilgisayarınıza başarıyla kuruldu."
!define MUI_FINISHPAGE_RUN "$INSTDIR\\Neutron.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Neutron'u şimdi çalıştır"
!define MUI_FINISHPAGE_RUN_NOTCHECKED

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
Page custom LicensePageCreate LicensePageLeave
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "Turkish"

Function .onInit
!if "${TARGET_ARCH}" == "x64"
  SetRegView 64
!endif
  InitPluginsDir
  ReadEnvStr $ProgramDataDir "ProgramData"
  StrCmp $ProgramDataDir "" 0 program_data_ready
  StrCpy $ProgramDataDir "C:\\ProgramData"
program_data_ready:
  ReadRegStr $LicenseDeviceHash HKLM "SOFTWARE\\Microsoft\\Cryptography" "MachineGuid"
  StrCmp $LicenseDeviceHash "" 0 device_hash_done
  StrCpy $LicenseDeviceHash "Cihaz kodu okunamadı"
device_hash_done:
  StrCpy $HadPreviousLicense "0"
  IfFileExists "$ProgramDataDir\\Neutron\\license\\activation.key" 0 license_backup_init_done
  CopyFiles /SILENT "$ProgramDataDir\\Neutron\\license\\activation.key" "$PLUGINSDIR"
  Rename "$PLUGINSDIR\\activation.key" "$PLUGINSDIR\\previous-activation.key"
  StrCpy $HadPreviousLicense "1"
license_backup_init_done:
FunctionEnd

Function LicensePageCreate
  !insertmacro MUI_HEADER_TEXT "Lisans aktivasyonu" "Neutron bu bilgisayara bağlanan geçerli bir lisans gerektirir."
  nsDialogs::Create 1018
  Pop $LicenseDialog
  ${If} $LicenseDialog == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 24u "Aşağıdaki cihaz kodunu lisans oluşturucuya girin. Üretilen NTR1 aktivasyon anahtarını bu sayfaya yapıştırmadan kurulum devam etmez."
  Pop $0
  ${NSD_CreateLabel} 0 30u 100% 10u "Cihaz kodu"
  Pop $0
  ${NSD_CreateText} 0 42u 100% 14u "$LicenseDeviceHash"
  Pop $LicenseDeviceInput
  SendMessage $LicenseDeviceInput 0x00CF 1 0
  ${NSD_CreateLabel} 0 60u 100% 16u "Program yazarıyla lisans kodu almak için iletişime geçin ve bu cihaz kodunu iletin."
  Pop $0
  ${NSD_CreateLabel} 0 80u 100% 10u "Aktivasyon anahtarı"
  Pop $0
  ${NSD_CreateText} 0 92u 100% 14u "$LicenseKey"
  Pop $LicenseInput
  ${NSD_CreateLabel} 0 114u 100% 22u "Anahtarın imzası, cihaz bağlantısı ve son kullanma tarihi kurulumdan önce doğrulanır."
  Pop $0
  nsDialogs::Show
FunctionEnd

Function LicensePageLeave
  ${NSD_GetText} $LicenseInput $LicenseKey
  StrCmp $LicenseKey "" license_input_error
  StrCpy $0 $LicenseKey 5
  StrCmp $0 "NTR1-" license_input_valid license_input_error
license_input_error:
  MessageBox MB_OK|MB_ICONEXCLAMATION "NTR1- ile başlayan aktivasyon anahtarını girin."
  Abort
license_input_valid:
  FileOpen $0 "$PLUGINSDIR\\activation.key" w
  FileWrite $0 "$LicenseKey"
  FileClose $0
FunctionEnd

Function un.onInit
!if "${TARGET_ARCH}" == "x64"
  SetRegView 64
!endif
FunctionEnd

Section "Neutron" SEC_MAIN
  SetShellVarContext all
  SetOutPath "$PLUGINSDIR\\NeutronStage"
  File /r "${APP_DIR}\\*.*"

  nsExec::ExecToStack /TIMEOUT=30000 '"$PLUGINSDIR\\NeutronStage\\Neutron.exe" --activate-license-file "$PLUGINSDIR\\activation.key"'
  Pop $0
  Pop $1
  IntCmp $0 0 license_verified license_verification_failed license_verification_failed
license_verification_failed:
  RMDir /r "$PLUGINSDIR\\NeutronStage"
  MessageBox MB_OK|MB_ICONSTOP "Lisans doğrulanamadı (kod $0). Anahtar hatalı, süresi dolmuş veya başka bir bilgisayara bağlı olabilir. Hiçbir Neutron servisi ya da koruması kurulmadı."
  SetErrorLevel 2
  Quit
license_verified:

  CreateDirectory "$INSTDIR"
  nsExec::ExecToStack /TIMEOUT=180000 '"$SYSDIR\\robocopy.exe" "$PLUGINSDIR\\NeutronStage" "$INSTDIR" /E /COPY:DAT /DCOPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS'
  Pop $0
  Pop $1
  StrCmp $0 "error" install_copy_failed
  StrCmp $0 "timeout" install_copy_failed
  IntCmp $0 8 install_copy_failed install_copy_ok install_copy_failed
install_copy_failed:
  StrCmp $HadPreviousLicense "1" restore_previous_license remove_new_license
restore_previous_license:
  CreateDirectory "$ProgramDataDir\\Neutron\\license"
  CopyFiles /SILENT "$PLUGINSDIR\\previous-activation.key" "$ProgramDataDir\\Neutron\\license"
  Goto install_copy_failure_done
remove_new_license:
  Delete "$ProgramDataDir\\Neutron\\license\\activation.key"
install_copy_failure_done:
  RMDir /r "$PLUGINSDIR\\NeutronStage"
  MessageBox MB_OK|MB_ICONSTOP "Kurulum dosyaları hedef klasöre kopyalanamadı (robocopy kodu $0). Güvenlik bileşenleri etkinleştirilmedi."
  SetErrorLevel 3
  Quit
install_copy_ok:
  RMDir /r "$PLUGINSDIR\\NeutronStage"
  Delete "$PLUGINSDIR\\activation.key"

  SetOutPath "$INSTDIR\\Recovery"
  File /oname=recover-neutron-boot.ps1 "${PROJECT_ROOT}\\tools\\security\\recover-neutron-boot.ps1"
  File /oname=remove-stuck-neutron.ps1 "${PROJECT_ROOT}\\tools\\security\\remove-stuck-neutron.ps1"
  SetOutPath "$INSTDIR"

  WriteUninstaller "$INSTDIR\\Uninstall.exe"
  CreateShortCut "$DESKTOP\\Neutron.lnk" "$INSTDIR\\Neutron.exe" "" "$INSTDIR\\Neutron.exe" 0
  CreateShortCut "$SMPROGRAMS\\Neutron.lnk" "$INSTDIR\\Neutron.exe" "" "$INSTDIR\\Neutron.exe" 0

  WriteRegStr HKLM "Software\\Neutron" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Neutron.exe" "" "$INSTDIR\\Neutron.exe"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "DisplayName" "Neutron"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "Publisher" "Neutron"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "DisplayIcon" "$INSTDIR\\Neutron.exe"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "UninstallString" '$\"$INSTDIR\\Uninstall.exe$\"'
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "QuietUninstallString" '$\"$INSTDIR\\Uninstall.exe$\" /S'
  WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "NoModify" 1
  WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "NoRepair" 1

  nsExec::ExecToStack /TIMEOUT=180000 '"$INSTDIR\\Neutron.exe" --provision-security'
  Pop $0
  Pop $1
  IntCmp $0 0 provision_ok provision_failed provision_failed
provision_failed:
  StrCpy $2 $0
  nsExec::ExecToStack /TIMEOUT=180000 '"$INSTDIR\\Neutron.exe" --prepare-uninstall'
  Pop $0
  Pop $1
  Delete "$DESKTOP\\Neutron.lnk"
  Delete "$SMPROGRAMS\\Neutron.lnk"
  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron"
  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Neutron.exe"
  DeleteRegKey HKLM "Software\\Neutron"
  !include "${UNINSTALL_INCLUDE}"
  Delete "$INSTDIR\\Recovery\\recover-neutron-boot.ps1"
  Delete "$INSTDIR\\Recovery\\remove-stuck-neutron.ps1"
  RMDir "$INSTDIR\\Recovery"
  Delete "$INSTDIR\\Uninstall.exe"
  RMDir "$INSTDIR"
  StrCmp $HadPreviousLicense "1" provision_restore_previous provision_remove_new_license
provision_restore_previous:
  CreateDirectory "$ProgramDataDir\\Neutron\\license"
  CopyFiles /SILENT "$PLUGINSDIR\\previous-activation.key" "$ProgramDataDir\\Neutron\\license"
  Goto provision_rollback_done
provision_remove_new_license:
  Delete "$ProgramDataDir\\Neutron\\license\\activation.key"
provision_rollback_done:
  Delete "$PLUGINSDIR\\previous-activation.key"
  MessageBox MB_OK|MB_ICONSTOP "Neutron'un zorunlu güvenlik bileşenleri kurulamadı (kod $2). Eksik kurulum geri alındı; program çalıştırılmadı."
  SetErrorLevel 4
  Quit
provision_ok:
  Delete "$PLUGINSDIR\\previous-activation.key"
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  IfFileExists "$INSTDIR\\Neutron.exe" cleanup_retry cleanup_fallback
cleanup_retry:
  nsExec::ExecToStack /TIMEOUT=180000 '"$INSTDIR\\Neutron.exe" --prepare-uninstall'
  Pop $0
  Pop $1
  IntCmp $0 0 cleanup_done cleanup_failed cleanup_failed
cleanup_failed:
  MessageBox MB_OK|MB_ICONEXCLAMATION "Standart bakım temizliği tamamlanamadı (kod $0). Kaldırıcı yalnız Neutron'a ait kayıtlar için yerleşik güvenli temizlemeye geçecek."
  Goto cleanup_fallback
cleanup_fallback:
  nsExec::Exec '"$SYSDIR\\schtasks.exe" /delete /tn "NeutronWatchdog" /f'
  Pop $0
  nsExec::Exec '"$SYSDIR\\sc.exe" stop "NeutronService"'
  Pop $0
  nsExec::Exec '"$SYSDIR\\sc.exe" delete "NeutronService"'
  Pop $0
  DeleteRegKey HKLM "SOFTWARE\\Microsoft\\AMSI\\Providers\\{ADACFA90-B877-414D-A818-2EA5291E290E}"
  DeleteRegKey HKLM "SOFTWARE\\Classes\\CLSID\\{ADACFA90-B877-414D-A818-2EA5291E290E}"
  SetRegView 32
  DeleteRegKey HKLM "SOFTWARE\\Microsoft\\AMSI\\Providers\\{ADACFA90-B877-414D-A818-2EA5291E290E}"
  DeleteRegKey HKLM "SOFTWARE\\Classes\\CLSID\\{ADACFA90-B877-414D-A818-2EA5291E290E}"
  SetRegView 64
  nsExec::ExecToStack /TIMEOUT=30000 '"$SYSDIR\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -NonInteractive -EncodedCommand JABFAHIAcgBvAHIAQQBjAHQAaQBvAG4AUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwA7ACAARwBlAHQALQBDAGkAbQBJAG4AcwB0AGEAbgBjAGUAIAAtAE4AYQBtAGUAcwBwAGEAYwBlACAAcgBvAG8AdABcAFMAZQBjAHUAcgBpAHQAeQBDAGUAbgB0AGUAcgAyACAALQBDAGwAYQBzAHMATgBhAG0AZQAgAEEAbgB0AGkAVgBpAHIAdQBzAFAAcgBvAGQAdQBjAHQAIAAtAEYAaQBsAHQAZQByACAAIgBpAG4AcwB0AGEAbgBjAGUARwB1AGkAZAA9ACcAYQBjADAAMAAwADgAYgAwAC0ANQA2ADQAYQAtADQANABmADgALQA4AGUAYwA3AC0AZgAyAGEAMgBkADgAMgBhADgAZgBlADgAJwAiACAAfAAgAFIAZQBtAG8AdgBlAC0AQwBpAG0ASQBuAHMAdABhAG4AYwBlADsAIABHAGUAdAAtAE4AZQB0AEYAaQByAGUAdwBhAGwAbABSAHUAbABlACAALQBOAGEAbQBlACAAJwBOAGUAdQB0AHIAbwBuAC0ARgBXAC0AKgAnACAAfAAgAFIAZQBtAG8AdgBlAC0ATgBlAHQARgBpAHIAZQB3AGEAbABsAFIAdQBsAGUA'
  Pop $0
  Pop $1
cleanup_done:
  nsExec::Exec '"$SYSDIR\\taskkill.exe" /F /T /IM Neutron.exe'
  Pop $0

  Delete "$DESKTOP\\Neutron.lnk"
  Delete "$SMPROGRAMS\\Neutron.lnk"
  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron"
  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Neutron.exe"
  DeleteRegKey HKLM "Software\\Neutron"

  !include "${UNINSTALL_INCLUDE}"
  Delete "$INSTDIR\\Recovery\\recover-neutron-boot.ps1"
  Delete "$INSTDIR\\Recovery\\remove-stuck-neutron.ps1"
  RMDir "$INSTDIR\\Recovery"
  Delete "$INSTDIR\\Uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd
