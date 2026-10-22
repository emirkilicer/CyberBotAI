# CYBERBOT — OWASP Bulgu Kapatma Planı

> Durum: `[ ]` bekliyor, `[~]` devam ediyor, `[x]` tamamlandı.
> Her görev için PoC/doğrulama komutu ve beklenen sonuç zorunludur.

## P0 — Üretim öncesi

- [x] **T1. Admin login throttle + IP allowlist + audit**
  - Değişecek: `core/middleware.py`, `config/settings.py`, `.env.example`, testler.
  - Kabul: 5 hatalı `/admin/login/` denemesinden sonra `429`; başarılı giriş sayacı sıfırlar; `ADMIN_IP_ALLOWLIST` dışından `/admin/` → `403`; denemeler audit log'a düşer.
  - PoC: 12 hatalı admin girişi; ilk denemeler 200, eşik sonrası 429. Allowlist testi 403.
  - Bağımlılık: yok.

- [x] **T2. Bootstrap 5.3.8 + SRI + CSP + Permissions-Policy**
  - Değişecek: `templates/base.html`, `templates/index.html`, `core/middleware.py`, testler.
  - Kabul: CDN linklerinde `integrity`/`crossorigin`; yanıtlarda nonce içeren CSP; `/admin/` için uyumlu CSP; inline script nonce'lu; `Permissions-Policy` başlığı.
  - PoC: `curl -I` CSP ve Permissions-Policy; HTML'de SRI ve nonce eşleşmesi.
  - Bağımlılık: yok.

- [x] **T3. Production fail-fast + Redis zorunluluğu**
  - Değişecek: `config/settings.py`, `.env`, `.env.example`, testler, README.
  - Kabul: `DJANGO_ALLOW_INSECURE_HTTP=False` iken secure cookie/HTTPS/HSTS/Redis/DB yoksa `ImproperlyConfigured`; lokal geliştirme açıkça `True` ile çalışır.
  - PoC: eksik env ile `manage.py check` hata verir; tam prod env ile `check --deploy` temiz.
  - Bağımlılık: T1/T2 ile aynı settings dosyası; sıralı.

- [x] **T4. İlk 2FA kaydı için out-of-band enrollment token**
  - Değişecek: `core/models.py`, migration, management command, `core/views.py`, `templates/setup_2fa.html`, testler.
  - Kabul: Normal signup token'sız devam eder; parola ile gelen mevcut/admin hesabı token olmadan QR göremez; geçerli token tek kullanımlık ve süreli.
  - PoC: Staff hesap → setup tanpa token `403`/QR yok; `issue_enrollment_token` ile QR; kod ile giriş; token tekrar kullanılamaz.
  - Bağımlılık: T1 (audit) ve T3 (settings).

- [x] **T5. Yedek kurtarma kodları**
  - Değişecek: yeni model/migration, `core/services/recovery.py`, `core/views.py`, `verify_2fa.html`, `recovery_codes.html`, testler.
  - Kabul: 2FA kurulumunda 10 tek kullanımlık kod üretilir; kodlar hash'li saklanır; TOTP yerine giriş yapar; aynı kod ikinci kez çalışmaz.
  - PoC: Kodla giriş başarılı; tekrar kullanım reddedilir.
  - Bağımlılık: T4 (2FA akışı).

- [x] **T6. Parola sıfırlama + e-posta doğrulama**
  - Değişecek: `config/settings.py`, `core/urls.py`, Django auth view'ları, şablonlar, `core/models.py`/migration, testler.
  - Kabul: Süreli tek kullanımlık reset e-postası; yeni parola ile giriş hâlâ 2FA ister. E-posta doğrulama token'ı üretilir; `REQUIRE_EMAIL_VERIFICATION=True` iken doğrulanmamış kullanıcı 2FA'ya geçemez.
  - PoC: `mail.outbox` reset maili; reset linki; eski parola reddi/yeni parola + 2FA. Doğrulama linki e-postayı verified yapar.
  - Bağımlılık: T4/T5.

## P1 — Sertleştirme

- [x] **T7. Yapılandırılmış log + alarm seviyesi + admin audit**
  - Değişecek: `core/audit.py`, `config/settings.py`, testler.
  - Kabul: JSON log opsiyonu; kilit/başarısız admin girişi WARNING/INFO audit; hassas veri yok.
  - PoC: `DJANGO_LOG_JSON=True` ile JSON satırı; admin hataları log'da.
  - Bağımlılık: T1.

- [x] **T8. AI girdi/çıktı moderasyonu**
  - Değişecek: `core/ai_safety.py`, `core/views.py`, `core/ai.py`, testler.
  - Kabul: Aşırı/boş/kontrol karakterli girdi reddedilir; bilinen jailbreak kalıpları bloklanır; çıktı kontrol karakterlerinden arındırılır ve uzunluk sınırlanır.
  - PoC: “ignore previous instructions” → 400; normal mesaj → 200; çıktı sanitize testi.
  - Bağımlılık: yok.

- [x] **T9. CI + bağımlılık kilidi**
  - Değişecek: `.github/workflows/security.yml`, `.github/dependabot.yml`, `requirements.in`/`requirements.lock`, README.
  - Kabul: CI test + bandit + pip-audit çalıştırır; hash'li lock ile kurulum.
  - PoC: workflow YAML lint/parse; `pip-audit -r requirements.lock` temiz; testler.
  - Bağımlılık: T3 (CI env).

## P2 — Altyapı / ileri seviye

- [x] **T10. PostgreSQL desteği ve prod DB zorunluluğu**
  - Değişecek: `config/settings.py`, requirements, `.env.example`, README.
  - Kabul: `DATABASE_URL` ile Postgres; prod'da SQLite reddedilir; lokal SQLite.
  - PoC: `DATABASE_URL` parse; `check`; migration dokümantasyonu.
  - Bağımlılık: T3.

- [x] **T11. Admin/IP ve ek güvenlik başlıkları**
  - `ADMIN_IP_ALLOWLIST`, `Permissions-Policy` (T1/T2 içinde).
  - Kabul/PoC: allowlist dışı 403; başlık mevcut.

- [~] **T12. WebAuthn/passkey — kapsam dışı bırakıldı**
  - Gerekçe: OWASP bulgusu değil, ileri seviye MFA enhancement. Tasarım notu README'de; ayrı iş paketi.

## Doğrulama komutları

```bash
python manage.py test
python manage.py check --deploy
bandit -q -r core config -x 'core/migrations,core/tests.py'
pip-audit -r requirements.lock
```

## Geri alma

- Migration'lar `0004+` ileri/geri alınabilir; TOTP secret migrasyonu `0003` geri alınabilir.
- `.env` değişiklikleri git dışında; prod env ayrı tutulur.
- CI/bağımlılık değişiklikleri ayrı commit'te tutulacak.

## PoC Sonuçları (22 Ekim 2026)

| Görev | PoC | Sonuç |
|---|---|---|
| T1 | 12 hatalı `/admin/login/` denemesi | İlk 5 deneme 200, sonrası **429**; audit `admin_login_failed/locked` |
| T1 | `ADMIN_IP_ALLOWLIST=10.0.0.1` dışından admin | **403** |
| T2 | `GET /` CSP + nonce | `Content-Security-Policy` nonce'lı; inline script nonce eşleşiyor |
| T2 | Bootstrap SRI | `bootstrap@5.3.8` + `integrity=sha384-...` + `crossorigin` |
| T3 | Eksik prod env ile settings import | `ImproperlyConfigured: Insecure production configuration` |
| T3 | Tam prod env ile settings import | Başarılı |
| T4 | Staff hesap, token'sız setup | QR yok; POST `403` |
| T4 | Geçerli token ile setup | QR gösterildi; TOTP ile giriş; token tek kullanım |
| T5 | Yedek kod ile giriş | Başarılı; aynı kod ikinci kez **reddedildi** |
| T5 | Profil üzerinden yeniden üretim | TOTP ile 10 yeni kod |
| T6 | Parola sıfırlama e-postası | `mail.outbox`; yeni parola + **2FA hâlâ zorunlu** |
| T6 | E-posta doğrulama | Token tek kullanım; `REQUIRE_EMAIL_VERIFICATION=True` iken setup bloklanıyor |
| T7 | JSON formatter | `event/user_id/ip/username_hash` alanları JSON'da |
| T8 | Prompt injection mesajı | `400`, model çağrılmadı |
| T8 | Kontrol karakterli çıktı | Temizlendi (`ok\x00\x07done` → `okdone`) |
| T9 | `pip-audit -r requirements.lock` | Bilinen zafiyet yok |
| T9 | `bandit` | Temiz |
| T10 | `DATABASE_URL` Postgres settings import | Başarılı (canlı DB geçişi dağıtım adımı) |
| T11 | CIDR allowlist `127.0.0.0/8` | **200**; diğer IP **403** |
| T12 | WebAuthn | Kapsam dışı; ayrı iş paketi |

Toplam otomatik test: **58 OK**.

## Kabul Edilen / Ertelenen Riskler

- **Kullanıcı adı enumerasyonu (düşük):** Kayıt formunda genel “not available” mesajı ve IP rate limit uygulandı. Kullanıcı adı tabanlı kayıtta tamamen gizlemek, kullanıcı deneyimini bozmadan mümkün değildir.
- **WebAuthn/passkey (T12):** OWASP bulgusu değil; ayrı ürün iş paketi.
- **AI moderasyonu:** RegeX tabanlı prompt-injection filtresi + çıktı sanitizasyonu; üretimde ayrı moderation servisi ve değerlendirme seti önerilir.
- **SIEM:** JSON log ve WARNING seviyeli olaylar hazır; merkezi toplama/alarm ortam yapılandırmasıdır.
- **PostgreSQL:** `DATABASE_URL` desteği ve prod zorunluluğu hazır; canlı veri taşıma/dağıtım adımı bu kod değişikliğinin dışındadır.
