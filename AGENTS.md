# AGENTS.md - NoMoreForbidden Stratejik Operasyon Kuralları

## Stratejik ve Teknik Roller

### Güvenlik Penetrasyon Uzmanı (Pentest Expert)
- **Sorumluluklar:**
  - `probes.py` içindeki bypass tekniklerini en son WAF ve erişim kontrolü trendlerine göre güncellemek.
  - Yeni header injection ve path manipulation yöntemleri keşfetmek ve sisteme entegre etmek.
  - Yanlış pozitif (false positive) oranlarını düşürmek için doğrulama mantığını iyileştirmek.

### Python Yazılım Mimarı (Software Architect)
- **Sorumluluklar:**
  - `nomoreforbidden` paketinin modülerliğini ve genişletilebilirliğini sağlamak.
  - `httpx` ve `requests` entegrasyonlarının performansını optimize etmek.
  - CLI arayüzünün (cli.py) kullanıcı dostu ve fonksiyonel kalmasını sağlamak.

### Laboratuvar ve Eğitim Geliştiricisi (Lab Developer)
- **Sorumluluklar:**
  - `renikApp` içindeki zafiyetli senaryoları geliştirmek ve gerçekçi hale getirmek.
  - Eğitim materyalleri ile uygulama arasındaki uyumu sağlamak.

## Uzmanlaşmış Roller

### Protokol Uzmanı
- HTTP/2 ve HTTP/3 spesifik bypass teknikleri üzerine çalışmak.
- Protokol bazlı smudging ve smuggling açıklarını test etmek.

### Test Otomasyon Mühendisi
- `tests/` dizinindeki entegrasyon testlerini (`renikApp` ile olanlar dahil) yönetmek.
- Her yeni teknik için otomatik test vakaları oluşturmak.

## Detaylı Sorumluluk Maddeleri
- **Etik Çerçeve:** Ajanlar, aracın sadece yasal ve izinli sızma testlerinde kullanılmasına yönelik uyarıları korumalıdır.
- **Kod Standartları:** "NO EMOJIS" kuralına uyulmalı, tüm log ve çıktı mesajları profesyonel bir dille yazılmalıdır.
- **Performans:** Çok sayıda isteğin gönderildiği bypass işlemlerinde, hedef sunucunun stabilitesini bozmamak için rate-limiting ve eşzamanlılık (concurrency) ayarları dikkatle yönetilmelidir.
- **Hata Yönetimi:** Bağlantı hataları ve beklenmedik HTTP yanıtları durumunda araç, mevcut tarama durumunu kaybetmeden devam edebilmelidir.
- **Dokümantasyon:** Her yeni bypass tekniği, README.md dosyasındaki "Özellikler" bölümüne ve `probes.py` içindeki ilgili dokümantasyon alanlarına eklenmelidir.

## Vault Bağlantısı

> Bu proje `C:\Users\skynet\Documents\Local Management\Projeler\Bug Bounty & Sızma Testi\NoMoreForbidden.md` dosyasında vault tarafından takip ediliyor. Bu projede çalışan bir AI ajanı, oturuma başlamadan önce o notu okumalı; oturum sonunda notun **Notlar**/**TODO** bölümlerini güncellemelidir.

- **Durum:** 🟡 Beklemede
- **Açıklama:** HTTP 403 Forbidden yanıtlarını atlatmak için onlarca bypass tekniğini sistematik biçimde deneyen CLI aracı; entegre `renikApp` eğitim laboratuvarı ve dinamik planlama motoru içeriyor.
- **Son vault senkronu:** 2026-06-21


<!-- local-management-sync:start -->
# Current Local Management vault synchronization

This source project is synchronized with the Local Management vault.

## Read before work
1. Canonical project card: C:\Users\skynet\Documents\Local Management\01-Projeler\Bug-Bounty-Pentest\NoMoreForbidden\P - NoMoreForbidden.md
2. There is no active context capsule. Do not create or promote a now priority without user approval.
3. Treat the canonical card as the current portfolio state; legacy notes are reference material only.

## Write back after work
1. If work changes the current understanding, update the active context capsule with verified findings, risks, and the next action.
2. Keep the project card next_action consistent with the context capsule.
3. Record durable choices in the vault decision record before claiming the work is complete.

## Safety
- Do not delete files without explicit user approval.
- Do not place secrets, credentials, or sensitive findings in the vault.
- Do not change portfolio horizon or create a now focus without user approval.
<!-- local-management-sync:end -->
