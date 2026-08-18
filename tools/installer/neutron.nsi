Unicode True

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

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
; The progress bar only advances on NSIS instructions, and almost all of the
; wall-clock time in this installer is spent inside three external calls
; (licence activation, robocopy, security provisioning) that each count as a
; single instruction. The result was a bar that filled while files were
; extracted, then sat motionless for minutes with no explanation -- not a
; hang, but a UI that stopped reporting.
;
; The fix is the status line above the bar, not the details list: the section
; below uses SetDetailsPrint textonly so each DetailPrint replaces that one
; line. The list pane stays hidden because a wall of file paths is noise to
; someone installing an application -- it belongs in the robocopy log, which
; is where the diagnostics actually live.
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
Var DeleteUserData
Var DeleteLicenseData
Var UninstallDialog
Var DeleteUserDataCheckbox
Var DeleteLicenseCheckbox
Var ProfileIndex
Var ProfileKey
Var ProfilePath

!ifndef APP_FILE_VERSION
  !error "APP_FILE_VERSION is required"
!endif

VIProductVersion "${APP_FILE_VERSION}"
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

; Risk acceptance, immediately before the activation page.
;
; Neutron quarantines files, registers Windows security components, writes
; firewall rules and has not been independently audited -- the README says so
; plainly, but nobody installing from the .exe ever sees the README. Consent
; belongs where the risk is actually taken.
;
; MUI's own licence page is used rather than a hand-built nsDialogs page
; because MUI_LICENSEPAGE_CHECKBOX already gates the Next button on the
; checkbox, which is exactly the required behaviour and one less thing to get
; subtly wrong.
!define MUI_PAGE_HEADER_TEXT "Risk bildirimi ve sorumluluk reddi"
!define MUI_PAGE_HEADER_SUBTEXT "Neutron'u kurmadan önce bu metni okuyun."
!define MUI_LICENSEPAGE_TEXT_TOP "Neutron deneysel bir güvenlik yazılımıdır ve kendi sorumluluğunuzda kullanılır."
!define MUI_LICENSEPAGE_TEXT_BOTTOM "Kuruluma devam edebilmek için aşağıdaki kutuyu işaretlemeniz gerekir."
!define MUI_LICENSEPAGE_CHECKBOX
!define MUI_LICENSEPAGE_CHECKBOX_TEXT "Okudum, anladım ve kabul ediyorum."
!insertmacro MUI_PAGE_LICENSE "${PROJECT_ROOT}\\tools\\installer\\risk-bildirimi.txt"

Page custom LicensePageCreate LicensePageLeave
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM

; Kaldırma sihirbazının veri sayfası. Bu bir MessageBox olarak başlamıştı:
; tek bir evet/hayır sorusu, kaldırıcı daha açılmadan sorulan, içinde
; karantinadaki dosyaların kalıcı olarak silineceği uyarısı da bulunan tek
; bir satır. Kişisel veriyi silmek ile lisansı korumak ayrı kararlardır ve
; ayrı kutuları hak ediyorlar.
;
; Sessiz kaldırmada (QuietUninstallString, /S) NSIS özel sayfaları hiç
; göstermez; o durumda un.onInit içindeki "hiçbir şeyi silme" varsayılanları
; geçerli olur. Otomatik bir kaldırma asla kullanıcı verisi silmez.
UninstPage custom un.OptionsPageCreate un.OptionsPageLeave

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

  ReadEnvStr $ProgramDataDir "ProgramData"
  StrCmp $ProgramDataDir "" 0 un_program_data_ready
  StrCpy $ProgramDataDir "C:\\ProgramData"
un_program_data_ready:

  ; Varsayılan: hiçbir şey silinmez. Kaldırma sihirbazındaki veri sayfası
  ; (un.OptionsPageCreate) bu iki değeri kullanıcının seçimine göre değiştirir;
  ; sessiz kaldırmada o sayfa hiç gösterilmediği için bu varsayılanlar kalır.
  StrCpy $DeleteUserData "0"
  StrCpy $DeleteLicenseData "0"
FunctionEnd

; Kaldırma sihirbazının veri sayfası.
;
; Kaldırıcı yalnızca $INSTDIR klasörünü siliyordu; makine öğrenmesi modelleri
; (profil başına yaklaşık 500 MB) ve karantina, kullanıcının varlığından
; haberdar olmadığı klasörlerde kalıyordu. İki karar da geri alınamaz ve
; birbirinden bağımsızdır, bu yüzden iki ayrı kutu:
;
;   · Karantinadaki dosyalar kullanıcının kendi dosyalarıdır; Neutron onları
;     yalnızca kenara aldı. Silinirlerse geri gelmezler.
;   · Lisans anahtarı bu bilgisayara bağlıdır. Silinirse yeniden kurulumda
;     yeni bir aktivasyon gerekir; bırakılırsa yeniden kurulum onu bulur.
Function un.OptionsPageCreate
  !insertmacro MUI_HEADER_TEXT "Kaldırma seçenekleri" "Neutron kaldırılırken hangi verilerin silineceğini seçin."
  nsDialogs::Create 1018
  Pop $UninstallDialog
  ${If} $UninstallDialog == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 26u "Program dosyaları, Windows servisi, AMSI kaydı ve güvenlik duvarı kuralları her durumda kaldırılır. Aşağıdakiler isteğe bağlıdır: işaretlemezseniz diskte kalır ve Neutron'u yeniden kurarsanız kullanılmaya devam eder."
  Pop $0

  ${NSD_CreateCheckBox} 0 32u 100% 10u "Kişisel verileri sil"
  Pop $DeleteUserDataCheckbox
  ${NSD_CreateLabel} 12u 44u 96% 34u "Ayarlar, tarama geçmişi ve veritabanı; makine öğrenmesi modelleri (kullanıcı profili başına yaklaşık 500 MB); ve KARANTINADAKİ DOSYALAR. Karantinadaki dosyalar sizin kendi dosyalarınızdır ve silinirlerse geri alınamaz."
  Pop $0

  ${NSD_CreateCheckBox} 0 82u 100% 10u "Lisans anahtarını sil"
  Pop $DeleteLicenseCheckbox
  ${NSD_CreateLabel} 12u 94u 96% 24u "Aktivasyon anahtarı bu bilgisayara bağlıdır. Silerseniz yeniden kurulumda yeni bir anahtar gerekir. İşaretlemezseniz anahtar diskte kalır ve yeniden kurulum onu kendisi bulur."
  Pop $0

  ${NSD_CreateLabel} 0 122u 100% 16u "Hiçbirini işaretlemezseniz yalnız program kaldırılır; verileriniz olduğu gibi kalır."
  Pop $0

  nsDialogs::Show
FunctionEnd

Function un.OptionsPageLeave
  ${NSD_GetState} $DeleteUserDataCheckbox $0
  ${If} $0 == 1
    StrCpy $DeleteUserData "1"
  ${Else}
    StrCpy $DeleteUserData "0"
  ${EndIf}
  ${NSD_GetState} $DeleteLicenseCheckbox $0
  ${If} $0 == 1
    StrCpy $DeleteLicenseData "1"
  ${Else}
    StrCpy $DeleteLicenseData "0"
  ${EndIf}

  ; Geri alınamaz tek adım burasıdır ve onayı, kutuyu işaretleyen tıklamadan
  ; ayrı olmalı: bir onay kutusu yanlışlıkla işaretlenebilir, bu soru
  ; işaretlenemez.
  StrCmp $DeleteUserData "1" 0 un_options_done
  MessageBox MB_YESNO|MB_ICONEXCLAMATION \
    "Karantinadaki dosyalar KALICI olarak silinecek ve geri alınamayacak.$\r$\n$\r$\nDevam edilsin mi?" \
    /SD IDYES IDYES un_options_done
  Abort
un_options_done:
FunctionEnd

; Removes one user profile's Neutron data folder. Called for every profile on
; the machine because the models are stored per user (%APPDATA%\Neutron) while
; the uninstaller itself runs elevated -- $APPDATA under elevation belongs to
; whichever account approved the UAC prompt, which is not necessarily the
; account that installed and used Neutron.
Function un.RemoveProfileData
  Exch $ProfilePath
  StrCmp $ProfilePath "" un_remove_profile_done
  IfFileExists "$ProfilePath\\AppData\\Roaming\\Neutron\\*.*" 0 un_remove_profile_done
  RMDir /r "$ProfilePath\\AppData\\Roaming\\Neutron"
un_remove_profile_done:
  Pop $ProfilePath
FunctionEnd

Section "Neutron" SEC_MAIN
  SetShellVarContext all
  ; textonly: each DetailPrint below replaces the single status line above the
  ; progress bar and writes nothing to the (hidden) list. "none" around the
  ; File extraction stops NSIS printing one line per extracted file, which
  ; would otherwise overwrite the status message thousands of times.
  SetDetailsPrint textonly
  DetailPrint "Kurulum dosyaları hazırlanıyor…"
  SetDetailsPrint none
  SetOutPath "$PLUGINSDIR\\NeutronStage"
  File /r "${APP_DIR}\\*.*"
  SetDetailsPrint textonly

  DetailPrint "Lisans doğrulanıyor ve kaydediliyor… (birkaç dakika sürebilir)"

  ; nsExec reports failures as the literal strings "error" and "timeout", not
  ; as exit codes, and IntCmp reads "timeout" as 0 -- i.e. as success. Without
  ; the two StrCmp guards below, a slow start here was silently treated as a
  ; verified licence: the installer carried on, nothing was ever written to
  ; ProgramData, and the installed app then asked for a licence the user had
  ; already entered. The robocopy call further down always had these guards;
  ; this one and the provisioning call did not.
  ;
  ; The timeout is generous because this is an Electron cold start from a
  ; freshly written temp staging directory, with the on-access scanner
  ; reading every file it touches. 30 s was not enough.
  nsExec::ExecToStack /TIMEOUT=420000 '"$PLUGINSDIR\\NeutronStage\\Neutron.exe" --activate-license-file "$PLUGINSDIR\\activation.key"'
  Pop $0
  Pop $1
  StrCmp $0 "error" license_verification_failed
  StrCmp $0 "timeout" license_verification_failed
  IntCmp $0 0 license_check_persisted license_verification_failed license_verification_failed

license_check_persisted:
  ; Trusting the exit code alone is what produced an installed app that asked
  ; for a licence the user had already entered: the activation reported
  ; success but nothing survived it. Check the artefact itself, not the
  ; report. HKLM is the copy the app reads first, so that is what must exist.
  ClearErrors
  ReadRegStr $2 HKLM "Software\\Neutron" "ActivationKey"
  IfErrors 0 license_verified
  StrCmp $2 "" 0 license_verified
  StrCpy $0 "kayit dogrulanamadi"
license_verification_failed:
  RMDir /r "$PLUGINSDIR\\NeutronStage"
  MessageBox MB_OK|MB_ICONSTOP "Lisans doğrulanamadı (kod $0). Anahtar hatalı, süresi dolmuş, başka bir bilgisayara bağlı olabilir ya da lisans kaydı diske yazılamadı. Hiçbir Neutron servisi ya da koruması kurulmadı."
  SetErrorLevel 2
  Quit
license_verified:
  DetailPrint "Lisans doğrulandı ve kaydedildi."
  DetailPrint "Çalışan Neutron bileşenleri durduruluyor…"

  ; A previous Neutron on this machine sits in the tray rather than exiting
  ; (window.on('close') hides it while protection is on -- see main.cjs), so a
  ; re-install or upgrade routinely finds Neutron.exe and its DLLs still
  ; open. robocopy then reports code 9 (files copied + some copy failures)
  ; with no indication of which file, because it was silently blamed on a
  ; generic "kopyalanamadı" instead. The uninstaller already stops the old
  ; process and service before touching files (see the comment in "Uninstall"
  ; below); the installer needs the exact same sequence for the same reason.
  ; Both calls are allowed to fail here -- there may be nothing running yet on
  ; a first install, and that is not an error.
  nsExec::Exec '"$SYSDIR\\taskkill.exe" /F /T /IM Neutron.exe'
  Pop $0
  nsExec::Exec '"$SYSDIR\\sc.exe" stop "NeutronService"'
  Pop $0
  Sleep 3000

  CreateDirectory "$INSTDIR"

  ; robocopy exit code 9 on every upgrade traced to exactly one file:
  ; NeutronAmsiProvider.dll, ERROR 32 "used by another process", four retries,
  ; retry limit exceeded.
  ;
  ; The taskkill above cannot fix it, and understanding why is the whole
  ; point: an AMSI provider is not loaded by Neutron. Windows loads it into
  ; every process that hands a buffer to AMSI -- powershell.exe, wscript.exe,
  ; Office, Explorer -- so the DLL is mapped into processes that have nothing
  ; to do with Neutron and that the installer has no business terminating.
  ; Unregistering it does not help either: that stops *new* loads, while every
  ; process already holding it keeps the image mapped until it exits.
  ;
  ; Windows forbids overwriting a mapped image but permits renaming one
  ; (image sections are opened with FILE_SHARE_DELETE, which is exactly why
  ; a running .exe can be renamed). So: unregister so nothing new picks it up,
  ; move the old copy aside so robocopy can write the new one in its place,
  ; and let the OS drop the renamed file at the next reboot.
  ;
  ; The suffix is counted rather than fixed because two upgrades without a
  ; reboot in between would otherwise collide on an .old that is itself still
  ; mapped and therefore still undeletable.
  StrCpy $4 "$INSTDIR\\resources\\runtime\\amsi\\${TARGET_ARCH}\\NeutronAmsiProvider.dll"
  IfFileExists "$4" 0 amsi_unlock_done
  DetailPrint "Önceki AMSI sağlayıcısı devre dışı bırakılıyor…"
  nsExec::Exec '"$SYSDIR\\regsvr32.exe" /s /u "$4"'
  Pop $0
  StrCpy $5 0
amsi_unlock_try:
  ClearErrors
  Rename "$4" "$4.old$5"
  IfErrors 0 amsi_unlock_renamed
  IntOp $5 $5 + 1
  IntCmp $5 8 amsi_unlock_failed amsi_unlock_try amsi_unlock_failed
amsi_unlock_renamed:
  ; Best effort now, guaranteed at reboot. Neither is required for the install
  ; to succeed -- the new DLL only needs the name to be free.
  Delete /REBOOTOK "$4.old$5"
  DetailPrint "Önceki AMSI sağlayıcısı kenara alındı."
  Goto amsi_unlock_done
amsi_unlock_failed:
  DetailPrint "Uyarı: önceki AMSI sağlayıcısı kenara alınamadı; kopyalama yine de denenecek."
amsi_unlock_done:

  ; /NFL /NDL /NJH /NJS previously suppressed robocopy's own file-level output
  ; entirely, so a failure produced nothing but a bare exit code -- which is
  ; why the AMSI lock above went undiagnosed for as long as it did. The log
  ; costs nothing on the success path (it is deleted below) and is the
  ; difference between guessing and reading the actual robocopy report.
  DetailPrint "Program dosyaları $INSTDIR klasörüne kopyalanıyor…"
  Delete "$TEMP\\Neutron-install-copy.log"
  nsExec::ExecToStack /TIMEOUT=900000 '"$SYSDIR\\robocopy.exe" "$PLUGINSDIR\\NeutronStage" "$INSTDIR" /E /COPY:DAT /DCOPY:DAT /R:3 /W:2 /LOG:"$TEMP\\Neutron-install-copy.log"'
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
  MessageBox MB_OK|MB_ICONSTOP "Kurulum dosyaları hedef klasöre kopyalanamadı (robocopy kodu $0). Güvenlik bileşenleri etkinleştirilmedi.$\r$\n$\r$\nTanılama: $TEMP\Neutron-install-copy.log"
  SetErrorLevel 3
  Quit
install_copy_ok:
  DetailPrint "Program dosyaları kopyalandı."
  Delete "$TEMP\\Neutron-install-copy.log"
  RMDir /r "$PLUGINSDIR\\NeutronStage"
  Delete "$PLUGINSDIR\\activation.key"
  DetailPrint "Kısayollar ve kayıt defteri girdileri oluşturuluyor…"

  SetOutPath "$INSTDIR\\Recovery"
  File /oname=recover-neutron-boot.ps1 "${PROJECT_ROOT}\\tools\\security\\recover-neutron-boot.ps1"
  File /oname=remove-stuck-neutron.ps1 "${PROJECT_ROOT}\\tools\\security\\remove-stuck-neutron.ps1"
  ; Kaldırma yardımcısı. Bu betik depoda zaten vardı ama hiçbir zaman
  ; kurulumla birlikte gelmiyordu -- yani tam da ona ihtiyaç duyulan durumda
  ; (Uninstall.exe silinmiş, servis takılmış, kurulum yarım kalmış) makinede
  ; bulunmuyordu. Artık kuruluyor ve Başlat menüsünden erişilebiliyor.
  File /oname=remove-neutron-completely.cmd "${PROJECT_ROOT}\\tools\\security\\remove-neutron-completely.cmd"
  File /oname=repair-neutron-powershell.cmd "${PROJECT_ROOT}\\tools\\security\\repair-neutron-powershell.cmd"
  SetOutPath "$INSTDIR"

  WriteUninstaller "$INSTDIR\\Uninstall.exe"
  CreateShortCut "$DESKTOP\\Neutron.lnk" "$INSTDIR\\Neutron.exe" "" "$INSTDIR\\Neutron.exe" 0
  ; 0.35 ve öncesi Başlat menüsüne tek bir düz kısayol koyuyordu. Yükseltmede
  ; önce o kaldırılır, yoksa menüde biri klasör biri kısayol olmak üzere iki
  ; Neutron görünür.
  Delete "$SMPROGRAMS\\Neutron.lnk"
  CreateDirectory "$SMPROGRAMS\\Neutron"
  CreateShortCut "$SMPROGRAMS\\Neutron\\Neutron.lnk" "$INSTDIR\\Neutron.exe" "" "$INSTDIR\\Neutron.exe" 0
  CreateShortCut "$SMPROGRAMS\\Neutron\\Neutron'u Kaldır.lnk" "$INSTDIR\\Uninstall.exe" "" "$INSTDIR\\Uninstall.exe" 0
  ; Kısayol bir .cmd dosyasını gösteriyor ve .cmd kısayolları kendiliğinden
  ; yönetici olarak açılmaz. Betiğin kendisi ilk iş olarak yetkiyi denetleyip
  ; ne yapılması gerektiğini yazıyor, bu yüzden kısayol sessizce başarısız
  ; olmaz; adında da yönetici gerektiği yazıyor.
  CreateShortCut "$SMPROGRAMS\\Neutron\\Neutron Kaldırma Yardımcısı (yönetici).lnk" "$INSTDIR\\Recovery\\remove-neutron-completely.cmd" "" "$INSTDIR\\Neutron.exe" 0

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
  ; Denetim Masası kaydının eksik kalan alanları. Programlar ve Özellikler
  ; listesinde Boyut sütunu boş görünüyordu ve "bu ne, nereden geldi, kime
  ; sorarım" sorusunun cevabı hiçbir yerde yazmıyordu -- bir güvenlik
  ; yazılımı için ikisi de kötü.
  ${GetSize} "$INSTDIR" "/S=0K" $4 $5 $6
  WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "EstimatedSize" "$4"
  ${GetTime} "" "L" $R0 $R1 $R2 $R3 $R4 $R5 $R6
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "InstallDate" "$R2$R1$R0"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "HelpLink" "https://github.com/omerbugrae/Neutron/issues"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "URLInfoAbout" "https://github.com/omerbugrae/Neutron"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron" "URLUpdateInfo" "https://github.com/omerbugrae/Neutron/releases"

  DetailPrint "Güvenlik bileşenleri etkinleştiriliyor… (bu adım birkaç dakika sürebilir, lütfen bekleyin)"
  nsExec::ExecToStack /TIMEOUT=1200000 '"$INSTDIR\\Neutron.exe" --provision-security'
  Pop $0
  Pop $1
  ; Same trap as the licence call above: "timeout" would parse as success and
  ; leave the machine reporting a provisioned installation that never ran.
  StrCmp $0 "error" provision_failed
  StrCmp $0 "timeout" provision_failed
  IntCmp $0 0 provision_ok provision_failed provision_failed
provision_failed:
  StrCpy $2 $0
  FileOpen $3 "$TEMP\Neutron-install-error.txt" w
  FileWrite $3 "Neutron ${APP_VERSION} security provisioning failed (code $2).$\r$\n$1$\r$\n"
  FileClose $3
  nsExec::ExecToStack /TIMEOUT=420000 '"$INSTDIR\\Neutron.exe" --prepare-uninstall'
  Pop $0
  Pop $1
  Delete "$DESKTOP\\Neutron.lnk"
  Delete "$SMPROGRAMS\\Neutron.lnk"
  Delete "$SMPROGRAMS\\Neutron\\Neutron.lnk"
  Delete "$SMPROGRAMS\\Neutron\\Neutron'u Kaldır.lnk"
  Delete "$SMPROGRAMS\\Neutron\\Neutron Kaldırma Yardımcısı (yönetici).lnk"
  RMDir "$SMPROGRAMS\\Neutron"
  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron"
  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Neutron.exe"
  DeleteRegKey HKLM "Software\\Neutron"
  !include "${UNINSTALL_INCLUDE}"
  Delete "$INSTDIR\\Recovery\\recover-neutron-boot.ps1"
  Delete "$INSTDIR\\Recovery\\remove-stuck-neutron.ps1"
  Delete "$INSTDIR\\Recovery\\remove-neutron-completely.cmd"
  Delete "$INSTDIR\\Recovery\\repair-neutron-powershell.cmd"
  Delete "$INSTDIR\\Recovery\\neutron-remove-root.txt"
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
  MessageBox MB_OK|MB_ICONSTOP "Neutron'un zorunlu güvenlik bileşenleri kurulamadı (kod $2). Eksik kurulum geri alındı; program çalıştırılmadı.$\r$\n$\r$\nTanılama: $TEMP\Neutron-install-error.txt"
  SetErrorLevel 4
  Quit
provision_ok:
  Delete "$TEMP\Neutron-install-error.txt"
  Delete "$PLUGINSDIR\\previous-activation.key"
  DetailPrint "Güvenlik bileşenleri etkinleştirildi."
  DetailPrint "Kurulum tamamlandı."
  SetDetailsPrint none
SectionEnd

Section "Uninstall"
  SetShellVarContext all

  ; Nothing below can delete a file that is still open. The desktop app and
  ; the LocalSystem service both run out of $INSTDIR, so they are stopped
  ; first -- previously taskkill ran near the end and the service was only
  ; ever asked to stop as part of the fallback, which left Neutron.exe and
  ; the service host locked while the deletes ran.
  nsExec::Exec '"$SYSDIR\\taskkill.exe" /F /T /IM Neutron.exe'
  Pop $0
  nsExec::Exec '"$SYSDIR\\sc.exe" stop "NeutronService"'
  Pop $0
  ; sc stop only submits the request; the SCM still has to take the service
  ; down and release its image. Without this pause the RMDir at the end fails
  ; and the installation is left half-removed.
  Sleep 3000

  IfFileExists "$INSTDIR\\Neutron.exe" cleanup_retry cleanup_fallback
cleanup_retry:
  nsExec::ExecToStack /TIMEOUT=420000 '"$INSTDIR\\Neutron.exe" --prepare-uninstall'
  Pop $0
  Pop $1
  ; A timeout here would parse as success and skip the fallback cleanup
  ; below, leaving the AMSI registration and the service behind on a machine
  ; the user believes is clean.
  StrCmp $0 "error" cleanup_failed
  StrCmp $0 "timeout" cleanup_failed
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
  ; --prepare-uninstall started another Neutron.exe; make sure that one is
  ; gone too before anything is deleted.
  nsExec::Exec '"$SYSDIR\\taskkill.exe" /F /T /IM Neutron.exe'
  Pop $0
  Sleep 1500

  Delete "$DESKTOP\\Neutron.lnk"
  Delete "$SMPROGRAMS\\Neutron.lnk"
  Delete "$SMPROGRAMS\\Neutron\\Neutron.lnk"
  Delete "$SMPROGRAMS\\Neutron\\Neutron'u Kaldır.lnk"
  Delete "$SMPROGRAMS\\Neutron\\Neutron Kaldırma Yardımcısı (yönetici).lnk"
  RMDir "$SMPROGRAMS\\Neutron"
  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Neutron"
  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Neutron.exe"
  DeleteRegKey HKLM "Software\\Neutron"

  !include "${UNINSTALL_INCLUDE}"
  Delete "$INSTDIR\\Recovery\\recover-neutron-boot.ps1"
  Delete "$INSTDIR\\Recovery\\remove-stuck-neutron.ps1"
  Delete "$INSTDIR\\Recovery\\remove-neutron-completely.cmd"
  Delete "$INSTDIR\\Recovery\\repair-neutron-powershell.cmd"
  Delete "$INSTDIR\\Recovery\\neutron-remove-root.txt"
  RMDir "$INSTDIR\\Recovery"
  Delete "$INSTDIR\\Uninstall.exe"
  RMDir "$INSTDIR"

  ; The generated manifest only lists what this build shipped. An upgrade
  ; from an older version, a stray log, or a file a locked process released
  ; late all leave $INSTDIR behind, and a leftover Program Files folder makes
  ; the next install look like it failed. Anything still here is Neutron's
  ; own -- the folder is Neutron-specific and the manifest already removed
  ; the known files -- so clear it and schedule whatever is still locked for
  ; deletion at the next boot rather than leaving it forever.
  IfFileExists "$INSTDIR\\*.*" 0 uninstall_user_data
  RMDir /r "$INSTDIR"
  IfFileExists "$INSTDIR\\*.*" 0 uninstall_user_data
  RMDir /r /REBOOTOK "$INSTDIR"

uninstall_user_data:
  ; İki ayrı karar, iki ayrı kutu (bkz. un.OptionsPageCreate). Lisans klasörü
  ; kasıtlı olarak kişisel verinin dışında tutuluyor: verileri silip lisansı
  ; korumak, yeniden kurulumda baştan aktivasyon gerektirmeden sıfırdan
  ; başlamanın tek yolu -- ve tersinin de mümkün olması gerekiyor.
  StrCmp $DeleteLicenseData "1" 0 uninstall_keep_license
  RMDir /r "$ProgramDataDir\\Neutron\\license"
uninstall_keep_license:

  StrCmp $DeleteUserData "1" 0 uninstall_prune_machine_dir

  ; Makine geneli durum: servis modunda veritabanı, karantina ve modeller
  ; burada yaşar. Lisans klasörü bilerek dışarıda: onu yalnız yukarıdaki
  ; kutu siler.
  RMDir /r "$ProgramDataDir\\Neutron\\data"

  ; Per-user state (models, database, quarantine, per-user licence). The
  ; elevated uninstaller's own $APPDATA is not necessarily the user who
  ; installed Neutron, so walk every profile registered on the machine
  ; instead of trusting it.
  SetShellVarContext current
  Push "$PROFILE"
  Call un.RemoveProfileData
  SetShellVarContext all

  StrCpy $ProfileIndex 0
uninstall_profile_loop:
  EnumRegKey $ProfileKey HKLM \
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList" $ProfileIndex
  StrCmp $ProfileKey "" uninstall_prune_machine_dir
  ReadRegStr $ProfilePath HKLM \
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\$ProfileKey" "ProfileImagePath"
  Push "$ProfilePath"
  Call un.RemoveProfileData
  IntOp $ProfileIndex $ProfileIndex + 1
  Goto uninstall_profile_loop

uninstall_prune_machine_dir:
  ; İçi boşaldıysa üst klasörü de bırakma. RMDir (/r yok) dolu bir klasöre
  ; dokunmaz, yani kullanıcı verisini korumayı seçtiyse burada hiçbir şey
  ; olmaz.
  RMDir "$ProgramDataDir\\Neutron"
SectionEnd
