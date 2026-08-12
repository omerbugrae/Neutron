# Çevrimdışı Neutron lisansları

Neutron lisansları Ed25519 ile imzalanır ve tek bir Windows cihazına bağlanır. Uygulama
özel anahtarı içermez; yalnızca doğrulama açık anahtarını içerir.

## Bir kez kurulum

Özel anahtar için proje dışında, yedeklenmiş bir klasör seçin. Bu komutu yalnız bir kez
çalıştırın; var olan anahtarların üzerine yazmaz:

```powershell
npm.cmd run license:keygen -- `
  --output C:\Users\omerb\Desktop\NeutronLicenseSecret `
  --public-output C:\Users\omerb\Desktop\Neutron\src\security\license-signing-public.pem
```

`license-signing-private.pem` asla Git'e, kurulum paketine veya kullanıcıya verilmez.
Ardından uygulamayı yeniden paketleyin; açık anahtar uygulamaya dahil edilir.

## Lisans üretme

Kullanıcı uygulamadaki etkinleştirme ekranından cihaz kimliğini sana verir. Aşağıdaki komut
bu cihaz için aktivasyon anahtarını üretir:

```powershell
npm.cmd run license:issue -- `
  --private-key C:\Users\omerb\Desktop\NeutronLicenseSecret\license-signing-private.pem `
  --device <kullanıcının-cihaz-kimliği> `
  --id musteri-0001 `
  --customer "Müşteri adı" `
  --edition Standard
```

Süreli lisans için örneğin `--expires 2027-08-12T00:00:00.000Z` ekleyin. Çıkan tek satır
`NTR1-XXXXX-XXXXX-...` biçimindedir; kullanıcı bunu Neutron etkinleştirme ekranına
yapıştırır. Tireler okunabilirlik içindir ve yapıştırırken korunabilir.

Bu sistem keygen üretimini ve farklı bilgisayarda lisans kullanımını engeller. Çevrimdışı
bir uygulama olduğundan, profesyonel tersine mühendisliğe karşı mutlak korsan engeli değildir.
