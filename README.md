# CYBERBOT

Yapay zeka destekli siber güvenlik asistanı. Django tabanlı uygulama; TOTP ile iki faktörlü kimlik doğrulama, yedek kurtarma kodları, korumalı admin paneli ve Google Gemini destekli sohbet içerir.

## Özellikler

- Kullanıcı kaydı, e-posta doğrulama ve güçlü parola politikası
- TOTP tabanlı 2FA (Google Authenticator uyumlu)
- Tek kullanımlık yedek kurtarma kodları
- Parola sıfırlama; sıfırlama sonrası 2FA hâlâ zorunlu
- Mevcut/admin hesaplar için tek kullanımlık enrollment token
- Admin paneli için 2FA, hız sınırı ve CIDR/IP allowlist
- Gemini destekli sohbet; girdi filtresi, çıktı sanitizasyonu ve güvenli render
- CSRF, CSP, SRI, güvenli cookie ve üretim fail-fast kontrolleri
- Denetim logları, JSON log desteği ve rate limiting
- 58 otomatik test; Bandit ve pip-audit temiz

## Teknolojiler

- Python 3.12, Django 5.2.17 LTS
- SQLite (geliştirme) / PostgreSQL (üretim)
- Redis (üretimde paylaşımlı rate limit)
- `pyotp`, `qrcode`, `cryptography` (Fernet), `argon2-cffi`
- `google-genai` ve Gemini `gemini-3.8-flash`
- Bootstrap 5.3.8, WhiteNoise

## Hızlı Başlangıç

```bash
git clone <repo-url>
cd cyberbot-ai-security

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
# Tekrarlanabilir kurulum:
# pip install --require-hashes -r requirements.lock

cp .env.example .env
```

`.env` içinde en az şu değerleri üretin:

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

- `DJANGO_SECRET_KEY`: Django imzalama anahtarı
- `TOTP_ENCRYPTION_KEY`: TOTP secret'larını şifreleyen Fernet anahtarı; yedekleyin
- `GEMINI_API_KEY`: Gemini API anahtarı

Veritabanını hazırlayıp uygulamayı başlatın:

```bash
python manage.py migrate
python manage.py collectstatic --noinput
python manage.py runserver 8080
```

Uygulama: `http://127.0.0.1:8080/`

## 2FA ve Admin

Normal kayıt akışında QR kod doğrudan gösterilir. Daha önce oluşturulmuş veya CLI ile açılmış hesaplar için tek kullanımlık enrollment token gerekir:

```bash
python manage.py createsuperuser
python manage.py issue_enrollment_token <username>
```

Komutun ürettiği `/setup-2fa/?token=...` bağlantısı 15 dakika geçerlidir ve yalnızca bir kez kullanılabilir.

Admin paneli `/admin/` yolundadır. Üretimde `ADMIN_IP_ALLOWLIST` ile erişimi sınırlandırın.

## Ortam Değişkenleri

Örnek ve açıklamalar için `.env.example` dosyasına bakın. Başlıca değişkenler:

| Değişken | Amaç |
|---|---|
| `DJANGO_DEBUG` | Debug modu; üretimde `False` |
| `DJANGO_ALLOW_INSECURE_HTTP` | Lokal HTTP geliştirme istisnası; üretimde `False` |
| `DJANGO_SECRET_KEY` | Django imzalama anahtarı |
| `DJANGO_ALLOWED_HOSTS` | İzinli host listesi |
| `TOTP_ENCRYPTION_KEY` | TOTP secret şifreleme anahtarı |
| `DATABASE_URL` | PostgreSQL bağlantısı (üretimde zorunlu) |
| `REDIS_URL` | Paylaşımlı rate-limit cache'i (üretimde zorunlu) |
| `ADMIN_IP_ALLOWLIST` | Admin için CIDR/IP allowlist |
| `DJANGO_REQUIRE_EMAIL_VERIFICATION` | E-posta doğrulama zorunluluğu |
| `GEMINI_API_KEY` | Gemini API anahtarı |
| `GEMINI_MODEL` | Varsayılan: `gemini-3.8-flash` |
| `DJANGO_LOG_JSON` | JSON log çıktısı |

## Testler

```bash
python manage.py test
```

Güvenlik taramaları:

```bash
bandit -q -r core config -x 'core/migrations,core/tests.py'
pip-audit -r requirements.lock
python manage.py check --deploy
```

## Üretim Notları

- `DJANGO_DEBUG=False` ve `DJANGO_ALLOW_INSECURE_HTTP=False`
- HTTPS, secure cookie, HSTS ve reverse proxy
- PostgreSQL + Redis + SMTP zorunlu
- `ADMIN_IP_ALLOWLIST` dolu olmalı
- `python manage.py collectstatic --noinput`
- `python manage.py check --deploy` temiz olmalı

Eksik güvenli yapılandırmada uygulama bilinçli olarak başlamaz.

## Dokümanlar

- `report.docx` — proje anlatımı ve güvenlik değerlendirme raporu
- `srs.pdf` — yazılım gereksinim belirtimi
- `SECURITY_TODO.md` — kapatılan bulgular ve PoC sonuçları

## Proje Yapısı

```text
config/                 Django ayarları ve URL'ler
core/                   Uygulama kodu
core/services/          TOTP, recovery, enrollment, e-posta, rate limit, audit
core/migrations/        Veritabanı migrasyonları
templates/              HTML şablonları
.github/workflows/      CI güvenlik hattı
requirements.in         Doğrudan bağımlılıklar
requirements.lock       Hash'li üretim kilidi
```
