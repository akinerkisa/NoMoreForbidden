# Devlog — NoMoreForbidden

## 2026-03-28

- **Yapı:** `nomoreforbidden` paketi (`core`, `cli`, `http_version`), kökte `nmf.py` sarmalayıcı, `python -m nomoreforbidden` desteği.
- **CLI:** `-i`, `-ip`, `--ip` aynı hedefe bağlı; `-v` artık bayrak (`store_true`). README güncellendi.
- **İstekler:** Hedef isteklerde tutarlı `verify=False` + `timeout=5` (Wayback API için `verify=True`).
- **HTTP sürüm:** `requests` içinde `raw.version` ataması kaldırıldı; `http.client` ile HTTP/1.0 / HTTP/1.1 gerçek denemeleri.
- **İstisnalar:** Bare `except` azaltıldı; Wayback için `JSONDecodeError`.
- **Test / CI:** `pytest` + GitHub Actions (Python 3.10–3.12).
- **Bağımlılık:** `requirements.txt` sadeleştirildi (`argparse` kaldırıldı); geliştirme için `requirements-dev.txt`.

## 2026-03-28 (v0.3)

- **`RunContext` + `requests.Session`:** `--proxy`, tekrarlanabilir `-H Name:Value`, `--cookie` (Cookie’yi `-H` sonrası yazar).
- **`--json`:** Banner yok; stdout’ta `version`, `target`, `proxy`, `findings[]` (kategori bazlı kayıtlar). `-v` ile daha fazla satır.
- **HTTP/1.0–1.1:** `http.client` hâlâ proxy kullanmıyor; JSON’da `note: does_not_use_proxy`.
- Sürüm: `0.3.0`, banner `v0.3`.

## 2026-03-28 (v0.4 — Faz 1)

- **`--output-format`:** `text` | `json` | `csv`; `--json` = `--output-format json`.
- **`--delay SEC`:** Her HTTP isteğinden sonra `time.sleep` (Session üzerinden).
- **Çıkış kodu:** `0` = en az bir `register_hit` (200/302, Wayback, HTTP sürüm vb.); `1` = sinyal yok.
- JSON çıktısına `hit` alanı eklendi.
- `RunContext`: `json_mode` → `output_format` + `structured`; `has_hit` / `register_hit()`.

## 2026-03-28 (v0.5 — Faz 2)

- **False-positive iyileştirmesi:** Sadece uzunluk değil, ilk `N` bayt için SHA-256 özet de karşılaştırılıyor.
- **`--fp-bytes N`:** FP karşılaştırmasında kaç baytın hash'lendiğini ayarlıyor (varsayılan `64`).
- **JSON/CSV bulguları:** `baseline_length`, `candidate_length`, `same_length`, `same_digest`, `baseline_digest`, `candidate_digest`, `digest_bytes` alanları.

## 2026-03-28 (v0.6 — Faz 3)

- **Yeni spoofing header'lar:** `Client-IP`, `True-Client-IP`, `X-Real-IP`, `X-Forwarded-Scheme`, `X-Forwarded-Prefix`.
- **Dosyadan genişletme:** `--payloads-file` ve `--headers-file` ile özel liste yükleme.
- **Ek metodlar:** `--methods` ile case-path denemesinde `HEAD`, `OPTIONS`, `PATCH` gibi metodlar.

## 2026-03-28 (v0.7 — Faz 4)

- **`--http2`:** HTTPS hedeflerde `httpx` ile opsiyonel HTTP/2 probe.
- **JSON kaydı:** `http_version` içinde `label=HTTP/2`, `version=20`, `note=uses_httpx_direct_client`.
- **Sınır:** HTTP/1.x probe'lar gibi bu kontrol de `requests.Session` proxy yapılandırmasını kullanmıyor.

## 2026-03-28 (v0.8 — Faz 5)

- **Refactor:** `core.py` artık uyum katmanı; istek ve FP yardımcıları `nomoreforbidden/request_utils.py`, ana probe akışları `nomoreforbidden/probes.py`.
- **Kalite:** `pyproject.toml` eklendi; proje meta, pytest ve ruff ayarları tek yerde.
- **CI:** GitHub Actions içine `ruff check .` adımı eklendi.

## 2026-03-28 (v0.8.1)

- **`--concurrency N`:** URL payload denemeleri için kontrollü thread havuzu.
- **Thread safety:** `RunContext.record()` ve `register_hit()` kilitle korunuyor.

## 2026-03-28 (v0.8.2)

- **`--rate-limit RPS`:** Session trafiği için global istek/saniye sınırı.
- **JSON:** Üst nesneye `schema_version: 1.0` alanı eklendi.

## 2026-03-28 (v0.8.3)

- **JSON summary:** `summary.total_findings`, `by_category`, `status_hits`, `possible_false_positives`, `errors`, `hit`.

## 2026-03-28 (v0.8.4)

- **Text summary:** Text mod sonunda kısa `Scan Summary:` satırı.

## 2026-03-28 (v0.9)

- **Dynamic path variants:** `//path`, trailing slash, `/.`, `; /`, `..;/` gibi ek varyasyonlar.
- **Method override probes:** `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`.

## 2026-03-28 (v1.0)

- **Profiles:** `safe`, `default`, `aggressive`, `proxy-aware`.
- **`--aggressive`:** Seçili profile ek olarak daha fazla payload/header/method ve daha yüksek concurrency.
- **`--only` / `--skip`:** Probe bazında çalışma seçimi (`nmf`, `wayback`, `ssl_switch`, `http_version`, `get_ip`).

## 2026-03-28 (v1.1)

- **Host header probes:** `Host`, `X-Host`, `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Original-Host`.
- **Header combinations:** `Accept`, `Content-Type`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-*` kombinasyonları.

## 2026-03-28 (v1.2)

- **`--timeout` / `--retries`:** İstek davranışını daha kontrollü hale getirir.
- **Response metadata:** `content_type`, `location`, `server`, `etag`, `content_length_header`.

## 2026-03-31 (v1.3)

- **False-positive scoring:** FP tespiti artık sadece uzunluk+digest değil; normalize içerik benzerliği, deny marker'ları, deny title marker'ları ve `/403` benzeri redirect sinyallerini de skorlar.
- **Structured output:** `same_normalized_text`, `baseline_title`, `candidate_title`, `deny_markers`, `deny_title_markers`, `fp_score`, `fp_reasons` alanları eklendi.
- **renikApp test alanı:** `/403/fake-200`, `/403/fake-302`, `/403/dynamic-forbidden`, `/403/same-length-different-body` senaryoları eklendi.
- **Baseline iyileştirmesi:** FP karşılaştırması artık site kökü yerine hedef URL'nin ilk deny cevabını referans alıyor.
- **Redirect metadata:** `final_url` ve `redirect_chain` structured çıktıya eklendi.
- **Kod temizliği:** `cli.py` ve testler artık doğrudan gerçek modülleri (`probes`, `request_utils`) kullanıyor; `core.py` sadece uyumluluk katmanı olarak sadeleştirildi.
- **renikApp temizlik:** Yinelenen `double_encoding_file_viewer()` tanımı kaldırıldı.
- **renikApp 403 refactor:** 403 senaryoları veri listesiyle merkezi hale getirildi; ortak 403 HTML cevapları `templates/403/scenario_page.html` içine taşındı.
- **Yeni 403 senaryoları:** `method-override-only`, `original-url-only`, `header-combo-only`, `fake-json-200`.
- **FP threshold tuning:** `--fp-threshold` ile false-positive eşiği kullanıcı tarafından ayarlanabilir hale geldi.
- **FP karar görünürlüğü:** Structured kayıtlara `fp_threshold` ve `fp_decision` alanları eklendi.
- **Content-type aware FP:** HTML/text sinyallerine ek olarak JSON cevaplar için `same_json_shape`, `same_json_text`, `json_deny_markers` ve content-type family alanları eklendi.
- **FP baseline strategy:** `--fp-baseline auto|target|root` ile referans karşılaştırma kaynağı seçilebilir hale geldi.
- **Analiz kolaylığı:** Structured çıktıya `confidence` ve `body_preview` alanları eklendi.
- **HTML FP tuning:** Kök sayfaya düşen cevaplar için `root_fallback` ve `title_mismatch` sinyalleri eklendi; root fallback + farklı başlık kombinasyonu artık daha güçlü FP işareti.

### İleride fikirler

- Rate limit ve eşzamanlı istek seçenekleri (dikkatli kullanım notu ile).
- Baseline seçim mantığını iyileştirip hedefin gerçek 403 cevabını referans olarak kullanmak.
- Redirect chain ve response body snippet alanlarını JSON çıktıya eklemek.

## 2026-04-14

- **X-Original-URL / X-Rewrite-URL:** Hem kök (`root`) hem de korumalı yolun kendisine (`same_path`) istek atılıyor; JSON’da `cache_header_target` ve `request_url` ile hangi strateji kullanıldığı görünüyor (renikApp `original-url-only` gibi senaryolar).
- **renikApp:** `Flask>=3.1.1` — Python 3.14’te kaldırılan `pkgutil.get_loader` yüzünden Flask 2.x ile uygulama açılmıyordu.
- **`renikApp/run_dev.py`:** debug/reloader kapalı sunucu; NMF entegrasyon testleri için uygun.
- **Testler:** `tests/test_renik_integration.py` — 403 bypass yolları + `fake-200` FP özeti; modül fixture ile sunucu yoksa `run_dev.py` ile geçici başlatma.
- **CI:** `renikApp/requirements.txt` kurulumu; `ruff` için `renikApp` `extend-exclude` (vuln lab kodu ayrı stil).
- **pytest:** `integration` işaretçisi kayıtlı.

### İleride fikirler

- Entegrasyon testinde rastgele boş port seçerek 5000 çakışmasını önlemek.

## 2026-04-14 (teknik genişletme)

- **URL payload:** Çift encoding (`%252e`), JVM stili (`;`, `;x=`), kontrol karakterleri (`%00`, `%0a`, CRLF), ek `%2e` varyantları.
- **Path variant:** `..%2f`, `%2e%2e/`, boşluk soneki, çift slash, `..` soneki.
- **IP / proxy:** `CF-Connecting-IP`, `X-Cluster-Client-IP`, `Fastly-Client-IP`, RFC 7239 `Forwarded` (for/proto/host).
- **Önbellek header:** `X-Original-URL` / `X-Rewrite-URL` için hem **path** hem **tam URL** (`cache_header_value_kind`); ek `X-Forwarded-URL`, `X-Proxy-URL`, `X-Forwarded-Path` (kategori `rewrite_header`).
- **Method override:** PATCH/DELETE ve ek `X-HTTP-Method: GET` denemeleri.
- **Header combo:** Googlebot UA, `X-Forwarded-Proto` + XFF, `X-Originating-IP`, `X-Remote-IP`, `X-Client-IP`.
- **Profil aggressive:** Ek payload sonekleri (`%252e`, `....//`, `%2f%2f`).

## 2026-04-14 (dry-run, allowlist, istek üst sınırı)

- **`nomoreforbidden/scope.py`:** `--allow-host` (tekrarlanabilir), `--allow-url-prefix` (tekrarlanabilir); hedef URL doğrulanır.
- **`nomoreforbidden/plan.py`:** `estimate_probe_http_upper_bound` — nmf fazları `probes` ile aynı sabitlerden sayılır (fp baseline üst sınırı: auto=2, diğer=1).
- **CLI:** `--dry-run` (HTTP yok; metin veya `--output-format json` ile tahmin özeti), `--max-requests N` (tahmini toplam > N ise çık kodu 2, gerçek tarama yok).
- **`probes` refaktör:** IP listesi, içerik kombinasyonları, cache hedefleri ve method override çiftleri ortak yardımcılarda toplandı (`collect_url_payloads`, `build_merged_ip_headers`, …).
- **Test:** `tests/test_scope_and_plan.py` (sayım regresyonu, allowlist, `--max-requests` subprocess).

## 2026-04-14 (dokümantasyon + --version)

- **CLI:** `--version` (sürüm yazdırıp çıkar; `-u` gerekmez).
- **README:** `--allow-host`, `--allow-url-prefix`, `--dry-run`, `--max-requests`, `--version`; dry-run JSON açıklaması; çıkış kodu tablosu (`2` = max-requests).
- **Test:** `test_version_exits_via_action` (`pytest` + `SystemExit`).

## 2026-04-14 (paketleme + sürüm kaynağı + CI smoke)

- **`nomoreforbidden/_version.py`:** Tek sürüm sabiti `VERSION`; `__init__.py` ve banner bu metni kullanır.
- **`pyproject.toml`:** `setuptools` build-backend, `dynamic` sürüm (`version.attr` → `_version.VERSION`), `[project.scripts]` → `nmf` → `run_cli`, pytest/ruff ayarları; kökteki `pytest.ini` kaldırıldı (ayarlar burada).
- **CLI:** `run_cli()` — konsol script `SystemExit(main())` ile çıkış kodu.
- **Geliştirme:** `tomli` yalnızca Python &lt; 3.11 testlerinde TOML okumak için (opsiyonel dev).
- **CI:** `pip install -e ".[dev]"`; smoke: `nmf --version`, `python -m nomoreforbidden`, `nmf.py`, dry-run JSON assert.
- **README:** `pip install .` / `pip install -e ".[dev]"`, `nmf` komutu, yetkilendirme + dry-run/scope kısa uyarı, dry-run JSON örneği.
- **Test:** `tests/test_version_consistency.py`.

## 2026-04-26

- **Repo hijyen:** `.gitignore` eklendi; `__pycache__/`, `*.py[cod]`, `*.egg-info/`, `.pytest_cache/`, `.ruff_cache/` artık izlenmiyor.
- **Commit planı:** Değişiklikler `kod/paketleme+test+ci` ve `dokümantasyon/devlog` olarak iki ayrı yerel commit'e bölündü.
- **Test düzeltmesi:** `tests/test_renik_integration.py` içinde `renikApp` subprocess artık `stderr=DEVNULL`; Flask request loglarının pipe'ı doldurup entegrasyon testlerini timeout'a düşürmesi engellendi.
- **Repo kapsamı:** `renikApp/` klasörü ana depoda takip dışı bırakıldı (`.gitignore`), nested-repo/submodule karmaşasını önlemek için varsayılan olarak dışarıda tutuluyor.
