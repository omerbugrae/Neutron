# Proton yayın paketleri

Bu araçlar, Proton tehdit tanımlarını tek bir şifreli ve dijital olarak imzalanmış
`.pdbx` dosyasına dönüştürür. Yeni npm veya Python paketi gerektirmez; Node.js'in
yerleşik `crypto` ve `zlib` modüllerini kullanır.

## Güvenlik modeli

- Paket içeriği AES-256-GCM ile şifrelenir.
- Paketin tamamı Ed25519 özel anahtarıyla imzalanır.
- Neutron yalnız gömülü açık anahtarla doğrulanabilen paketleri kabul edecektir.
- Özel imzalama anahtarı ve AES anahtarı hiçbir Git deposuna eklenmemelidir.
- Şifreleme, public Release dosyasının doğrudan okunmasını engeller; istemci veriyi
  kullanabildiği için kararlı tersine mühendisliğe karşı mutlak gizlilik sağlamaz.

## 1. Anahtarları bir kez oluşturma

Anahtar klasörü proje dışında olmalıdır:

```powershell
npm.cmd run proton:keygen -- --output C:\Neutron-Secrets
```

Oluşan `proton-signing-private.pem` ve `proton-encryption.key` dosyalarını çevrimdışı,
şifreli bir ortamda yedekleyin. Kaybolurlarsa eski Neutron kurulumları için güvenilir
güncelleme üretilemez. Ele geçirilirlerse yeni anahtar kimliğiyle uygulama güncellemesi
yayınlanmalıdır.

## 2. Tanım kaynağını hazırlama

Gerçek tanım kaynağını public repoda tutmayın. Biçim için
`tools/proton/examples/definitions.json` dosyasını örnek alın. YARA yolları JSON
dosyasının bulunduğu klasöre göre çözülür ve bu klasörün dışına çıkamaz.

Her sürümde zorunlu olan `provenance` kaydı veri setinin kaynağını, HTTPS adresini,
toplanma zamanını, lisansını ve insan inceleme politikasını içerir. Üretim paketine
yalnızca kaynak-atıflı, yinelenmeyen, YARA ile derlenmiş ve temiz dosya korpusunda
yanlış-pozitif testi yapılmış göstergeler alınmalıdır.

Sürüm biçimi `x.xx.xxx` olmalıdır. Aynı SHA-256 veya YARA dosya adı iki defa
kullanılamaz.

## 3. Paketi oluşturma

## Gerçek tehdit istihbaratı toplama

`proton:collect`, API anahtarını yalnızca toplama makinesinin ortam değişkeninden alır;
anahtarı ne aday tanım dosyasına ne de Proton paketine yazar. Malware örnek dosyalarını
indirmez veya çalıştırmaz. URLhaus'tan yalnızca aktif `malware_download` URL'lerini,
URLhaus ve MalwareBazaar'dan ise geçerli SHA-256 ve dosya boyutu bulunan metadataları alır.

Önce [abuse.ch Authentication Portal](https://auth.abuse.ch/) üzerinden bir Auth-Key alın.
PowerShell oturumunda (kalıcı olarak kaydetmeden) anahtarı verin:

```powershell
$env:NEUTRON_ABUSECH_AUTH_KEY = 'Auth-Key-buraya'
```

Ardından mevcut tanım kaynağından yeni bir *aday* sürüm üretin. Çıktı adı daha önce
olmamalıdır; araç üzerine yazmaz:

```powershell
npm.cmd run proton:collect -- `
  --source C:\Neutron-Proton-Source\definitions.json `
  --version 1.00.007 `
  --output C:\Neutron-Proton-Source\candidates\definitions-1.00.007.json
```

Çıkan adayı gözden geçirin. Ardından aynı dosyayı normal yayın zincirine verin:

```powershell
npm.cmd run proton:publish -- `
  --source C:\Neutron-Proton-Source\candidates\definitions-1.00.007.json `
  --keys C:\Users\omerb\Desktop\NeutronSecret `
  --output C:\Users\omerb\Desktop\NeutronProtonRelease
```

Üretimde bunu zamanlanmış CI işi veya ayrı, korumalı bir toplama makinesinde çalıştırın.
Neutron istemcileri bu API'lere bağlanmaz; sadece imzalanmış Release'i indirir. Bu sayede
Auth-Key dağıtım paketine ve kullanıcı bilgisayarına girmez.

İnceleme aşamasını atlamak istemezseniz yukarıdaki iki komutu kullanın. Aynı işlemi tek
komutta yapmak için (yalnızca önce aday üretimini deneyip güvendiğinizde):

```powershell
npm.cmd run proton:sync -- `
  --source C:\Neutron-Proton-Source\definitions.json `
  --version 1.00.007 `
  --keys C:\Users\omerb\Desktop\NeutronSecret `
  --output C:\Users\omerb\Desktop\NeutronProtonRelease
```

`proton:sync`, geçici aday dosyasını yerel geçici klasörde oluşturur; imza doğrulaması
başarılı olursa GitHub Release'i yayımlar ve ardından bu geçici dosyayı siler.

## Otomatik günlük yayın (GitHub Actions)

`.github/workflows/proton-feed.yml` her gün 03:17 UTC'de yeni Proton paketi oluşturur;
ayrıca GitHub Actions ekranından **Run workflow** ile elle sürüm numarası vererek
çalıştırılabilir. `NeutronProton` deposunda aşağıdaki Actions Secrets değerlerini ekleyin:

- `NEUTRON_ABUSECH_AUTH_KEY`: abuse.ch Auth-Key.
- `NEUTRON_PROTON_ENCRYPTION_KEY`: `proton-encryption.key` dosyasının tek satırlık içeriği.
- `NEUTRON_PROTON_SIGNING_PRIVATE_KEY`: `proton-signing-private.pem` dosyasının tüm içeriği.
- `NEUTRON_PROTON_SIGNING_PUBLIC_KEY`: `proton-signing-public.pem` dosyasının tüm içeriği.

Bu workflow **NeutronProton** deposunda çalışmalıdır ve kendi deposuna Release oluşturur.
Dosyayı NeutronProton deposuna koyun; Actions ayarlarında `Workflow permissions` değeri
**Read and write permissions** olmalıdır. Böylece imzalama özel anahtarı, Neutron uygulama
kodu deposunda veya kullanıcı bilgisayarlarında bulunmaz.

```powershell
npm.cmd run proton:pack -- `
  --source C:\Neutron-Proton-Source\definitions.json `
  --keys C:\Neutron-Secrets `
  --output C:\Neutron-Proton-Release
```

Araç aşağıdaki iki dosyayı üretir:

```text
proton-1.00.002.pdbx
proton-1.00.002.pdbx.sig
```

Bu iki dosya `NeutronProton` GitHub deposundaki `proton-v1.00.006` Release'ine
yüklenebilir.

## Tek komutla oluşturma ve GitHub'da yayımlama

GitHub CLI kurulmuş ve `gh auth login` ile oturum açılmışsa paketleme, ikinci
doğrulama ve Release yükleme işlemleri tek komutla yapılabilir:

```powershell
npm.cmd run proton:publish -- `
  --source C:\Neutron-Proton-Source\definitions.json `
  --keys C:\Users\omerb\Desktop\NeutronSecret `
  --output C:\Users\omerb\Desktop\NeutronProtonRelease
```

Komut varsayılan olarak `omerbugrae/NeutronProton` deposunu kullanır. Önce GitHub
oturumunu ve aynı etiketli bir Release bulunmadığını kontrol eder. Paket yerelde
zaten varsa onu yeniden şifrelemek yerine imzasını ve şifresini tekrar doğrular.
Doğrulama tamamlanmadan ağ üzerinde yayın oluşturmaz. Aynı sürümün üzerine yazmaz.

Özel imzalama anahtarı ve AES anahtarı hiçbir `gh` komutuna verilmez; GitHub'a
yalnız `.pdbx` ile `.pdbx.sig` dosyaları yüklenir.

## 4. Yayından önce doğrulama

```powershell
npm.cmd run proton:verify -- `
  --package C:\Neutron-Proton-Release\proton-1.00.006.pdbx `
  --signature C:\Neutron-Proton-Release\proton-1.00.006.pdbx.sig `
  --public-key C:\Neutron-Secrets\proton-signing-public.pem `
  --encryption-key C:\Neutron-Secrets\proton-encryption.key
```

Doğrulama aracı imzayı, paket özetlerini, AES-GCM etiketini ve çözülen yükün şemasını
kontrol eder. Tanımlar terminale yazdırılmaz.

## Paket sınırları

- Kaynak/veri açılmış durumda en fazla 64 MiB
- Tek YARA dosyası en fazla 2 MiB
- Toplam YARA içeriği en fazla 16 MiB
- En fazla 256 YARA dosyası
- En fazla 1.000.000 hash imzası

Bu sınırlar bozuk veya kötü amaçlı paketlerin aşırı bellek tüketmesini önlemek için
hem üretici hem de Neutron güncelleme istemcisi tarafında uygulanmalıdır.
