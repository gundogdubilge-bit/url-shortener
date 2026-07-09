# ACI LinkKısalt - Kurulum Rehberi

## Gereksinimler
- Python 3.10+
- Git

## Kurulum Adımları

### 1. Projeyi indir
```
git clone https://github.com/gundogdubilge-bit/url-shortener.git
cd url-shortener
```

### 2. Gerekli kütüphaneleri kur
```
pip install -r requirements.txt
```

### 3. SSL sertifikası oluştur
```
python gen_cert.py
```

### 4. Sertifikayı Windows'a tanıt (Chrome için)
```
certutil -addstore -user Root cert.pem
```

### 5. Hosts dosyasına ekle (Yönetici olarak Notepad ile aç)
Dosya: `C:\Windows\System32\drivers\etc\hosts`
Şu satırı ekle:
```
127.0.0.1    aci1878
```

### 6. Port yönlendirme (Yönetici PowerShell)
```
netsh interface portproxy add v4tov4 listenport=443 listenaddress=0.0.0.0 connectport=8443 connectaddress=127.0.0.1
```

### 7. Uygulamayı başlat
```
python -m uvicorn main:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

### 8. Tarayıcıda aç
```
https://aci1878
```

## Giriş Bilgileri
- E-posta: admin@aci.k12.tr
- Şifre: Sistem yöneticisinden alınız

---

## Okul Bilgisayarında İlk Kurulum

Bu adımları okul bilgisayarında **bir kez** yapmanız yeterli.

### Adım 1 — Python ve Git kurulu mu kontrol et
PowerShell'de şunu çalıştırın:
```
python --version
git --version
```
Kurulu değilse:
- Python: https://python.org/downloads → "Add to PATH" seçeneğini işaretleyin
- Git: https://git-scm.com/download/win → varsayılan ayarlarla kurun

### Adım 2 — Projeyi bilgisayara indir
```
git clone https://github.com/gundogdubilge-bit/url-shortener.git
cd url-shortener
```

### Adım 3 — Kütüphaneleri kur
```
pip install -r requirements.txt
```

### Adım 4 — SSL sertifikası oluştur
```
python gen_cert.py
```

### Adım 5 — Sertifikayı Chrome'a tanıt
```
certutil -addstore -user Root cert.pem
```

### Adım 6 — Hosts dosyasını düzenle (yönetici gerekli)
Notepad'i yönetici olarak açın, şu dosyayı açın:
```
C:\Windows\System32\drivers\etc\hosts
```
En alta şu satırı ekleyip kaydedin:
```
127.0.0.1    aci1878
```

### Adım 7 — Port yönlendirme (yönetici PowerShell)
```
netsh interface portproxy add v4tov4 listenport=443 listenaddress=0.0.0.0 connectport=8443 connectaddress=127.0.0.1
```

### Adım 8 — Uygulamayı başlat
```
cd url-shortener
python -m uvicorn main:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

### Adım 9 — Tarayıcıda aç
```
https://aci1878
```

> **Not:** Adım 6 ve 7 yönetici yetkisi gerektirir. Bu adımlarda sorun yaşarsanız IT'den yardım isteyin.

---

## Güncelleme (her iki bilgisayarda)
Değişiklikleri çekmek için:
```
git pull
```
Değişiklikleri göndermek için:
```
git add .
git commit -m "güncelleme açıklaması"
git push
```
