# ACI LinkKısalt - Kurulum Rehberi

## Gereksinimler
- Python 3.10+
- Git

## Kurulum Adımları (yeni bir bilgisayarda bir kez yapılır)

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

> **Not:** Adım 5 ve 6 yönetici yetkisi gerektirir. Sorun yaşarsanız IT'den yardım isteyin.

## Giriş Bilgileri
- E-posta: admin@aci.k12.tr
- Şifre: Sistem yöneticisinden alınız

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
