# Blueprint: Detection Feasibility & Rule Recommendation Engine

**Konteks:** Fase build/pre-implementation project IMS — dipakai dari raw log sample, baik sebelum pipeline ingest dibangun maupun index yang sudah jalan tapi field-nya belum dinormalisasi ke ECS. Output-nya bukan cuma rule bundle, tapi juga input buat keputusan desain ingest/index dan scoping SOW.
**Status:** Draft blueprint v1 — acuan eksekusi
**Constraint utama:** Fully on-prem/offline. Tidak ada raw log atau data klien yang dikirim ke layanan AI/cloud eksternal mana pun.

---

## 1. Masalah & Tujuan

**Masalah saat ini:** setiap project implementation, tim IMS harus manual memilah raw log klien, memetakan field mana yang relevan, dan menentukan sendiri detection use case apa yang bisa dibuat dari situ. Proses ini repetitif, bergantung pada pengalaman personal, dan sulit di-scale ketika beberapa project berjalan paralel.

**Tujuan engine ini:** dari input raw log sample — baik sample mentah hasil discovery/onboarding klien, maupun export index yang sudah berjalan di Elastic tapi field-nya belum dinormalisasi ke ECS — engine secara otomatis:

1. Mengidentifikasi kandidat detection rule yang feasible, lengkap dengan mapping ke MITRE ATT&CK dan tipe rule Elastic yang sesuai
2. Kalau tidak ada kandidat yang feasible, mengeluarkan **reasoning terstruktur** kenapa (bukan cuma "tidak bisa")
3. Memberi estimasi performa (potensi noise/alert volume) sebelum rule benar-benar dibuat di Kibana
4. Menghasilkan draft runbook siap-review, bukan draft rule mentah
5. Menghasilkan rekomendasi untuk keputusan desain implementation itu sendiri — field/log source apa yang perlu diprioritaskan onboarding-nya, dan detection use case apa yang realistis dicantumkan di SOW/project plan

Output akhirnya selalu lewat **review analyst** sebelum masuk production — engine ini mempercepat proses triase awal di fase build, bukan menggantikan keputusan akhir.

## 2. Validasi Konsep

Ide ini feasible. Kombinasi tiga hal yang diusulkan — feasibility check, hypothesis-rejection reasoning, dan prediction — belum jadi fitur standar di produk manapun setahu penulis, jadi ini genuinely bernilai untuk dibangun.

Poin penting yang membentuk desain di bawah:

- **Jangan reinvent matching-nya dari nol.** Sigma (format deteksi YAML terbuka) sudah punya korpus ribuan rule yang dipetakan ke MITRE ATT&CK, dan pySigma (library resmi) punya backend converter ke Elastic. Semua jalan lokal, tanpa panggilan API apa pun — pas dengan constraint confidentiality. Manfaatkan sebagai layer pertama matching.
- **Beda posisi dengan AI Agent Elastic** — fitur itu bekerja di dalam Kibana, terhadap index yang sudah live dan sudah bermapping, untuk SOC analyst yang menulis/tuning rule di sistem yang sudah jalan. Di fase build IMS, index itu belum tentu ada — kerja dimulai dari raw log sample sebelum pipeline ingest dibangun, untuk memutuskan apa yang perlu di-onboard dan apa yang realistis masuk scope project. Bukan duplikasi fitur yang sudah ada, tapi mengisi tahapan yang lebih awal dan memang belum disentuh tooling manapun.
- **Bagian yang genuinely baru dan layak difokuskan:** (a) logic pemilihan tipe rule Elastic yang tepat, (b) modul hypothesis-validation untuk kasus reject, (c) prediction/backtest sebelum deploy, (d) auto-generate runbook sesuai format tim.
- **Batas realistis:** matching berbasis heuristic/taxonomy punya ceiling — akurasinya bergantung penuh pada seberapa lengkap knowledge base-nya dikurasi, dan itu bukan proyek sekali-jadi, tapi terus dirawat. Untuk log source yang proprietary/tidak umum, sistem ini akan sering bilang "tidak ada match otomatis" — itu bukan berarti "tidak bisa dideteksi", cuma berarti butuh analyst turun tangan manual. Dokumentasikan gap ini dengan jujur, jangan sampai output engine dibaca sebagai kesimpulan final oleh siapa pun yang tidak terlibat langsung di prosesnya.

## 3. Prinsip Desain

- **Deterministic, bukan generatif** — semua keputusan matching berbasis schema/pattern/taxonomy yang bisa ditelusuri, bukan model bahasa
- **Fully offline** — bisa jalan air-gapped kalau perlu; korpus Sigma & dataset MITRE ATT&CK didownload sekali lalu disimpan lokal
- **Batch/asynchronous, bukan interaktif blocking** — dijalankan sebagai job di background terhadap satu file/export log. Trigger scan, lanjut kerjaan implementation lain, balik lagi pas hasil siap — ini yang bikin engine-nya benar-benar menghemat waktu, bukan cuma memindahkan waktu tunggu dari "mapping manual" ke "nunggu di depan layar". Ini bukan berarti UI-nya harus berasa lambat untuk kasus umum — satu file ukuran wajar tetap bisa kasih hasil hampir instan; prinsip async ini yang penting justru untuk file besar/job yang genuinely makan waktu lama
- **Explainable by default** — setiap match ATAU reject harus punya reasoning yang tercatat, bukan cuma skor angka
- **Human-in-the-loop wajib** — tidak ada rule yang otomatis deploy ke production
- **Extensible** — taxonomy internal harus mudah ditambah seiring pengalaman project baru (mirip taxonomy 15-kategori yang sudah dibangun untuk Cloudflare WAF — pola yang sama bisa direplikasi di sini)
- **Tidak dikunci ke MITRE ATT&CK saja** — struktur matching dibuat generic supaya bisa nambah mapping ke NIST CSF, CIS Controls, atau D3FEND kalau dibutuhkan project tertentu

## 4. Arsitektur Pipeline

```
[Raw Log: CSV / JSON / Syslog / Text]
                │
                ▼
   ┌─────────────────────────────┐
   │ 1. Ingestion & Normalisasi   │
   └─────────────────────────────┘
                │
                ▼
   ┌─────────────────────────────┐
   │ 2. Field & Schema Profiling  │
   └─────────────────────────────┘
                │
                ▼
   ┌─────────────────────────────┐
   │ 3. Feasibility Matching      │──── korpus Sigma (offline)
   │    Engine                    │──── taxonomy internal (kurasi tim)
   └─────────────────────────────┘
                │
        ┌───────┴───────┐
        ▼               ▼
     MATCH           NO MATCH
        │               │
        ▼               ▼
┌───────────────┐ ┌─────────────────────┐
│ 4. Rule Type   │ │ 5. Hypothesis &      │
│    Classifier  │ │    Validation Module │
└───────────────┘ └─────────────────────┘
        │               │
        ▼               │
┌───────────────┐       │
│ 6. Prediction  │       │
│  & Backtest    │       │
└───────────────┘       │
        │               │
        └───────┬───────┘
                ▼
   ┌─────────────────────────────┐
   │ 7. Runbook Generator         │
   └─────────────────────────────┘
                │
                ▼
   ┌─────────────────────────────┐
   │ 8. Human Review Checkpoint   │
   └─────────────────────────────┘
```

## 5. Detail Modul

### 5.1 Ingestion & Normalisasi
- Input, dua skenario:
  - **Sample mentah pre-onboarding** — CSV/JSON/syslog dari klien saat discovery/scoping, sebelum pipeline ingest resmi dibangun
  - **Export index yang sudah jalan di Elastic tapi belum ECS-normalized** — misal hasil export dari Kibana Discover atau Elasticsearch scroll/search API, field masih nama vendor asli (`srcip`, `ClientIP`, dst), belum lewat ingest pipeline yang benar
- Auto-detect delimiter/struktur, atau terima schema hint manual dari user
- Normalisasi ke schema kanonikal ala ECS (Elastic Common Schema) sebisa mungkin, karena target akhirnya memang Elastic
- Output: record terstruktur + inventory field awal — inventory ini juga jadi input awal buat desain index template/pipeline yang akan dibangun di fase implementation

### 5.2 Field & Schema Profiling Engine
- Per field, hitung: cardinality, null rate, distribusi value
- Entity recognition berbasis regex: IP (v4/v6), domain, hash (md5/sha1/sha256), email, URL, port, file path, pola process name, dst
- Hasil akhir: **log fingerprint** — ringkasan terstruktur "log ini kemungkinan besar dari kategori/produk/service apa" (analog ke field `category`/`product`/`service` di logsource Sigma)
- **Klasifikasi tipe data** — log fingerprint juga menandai log ini termasuk kategori mana: Network Logs, Endpoint Data, Authentication Logs, Application Logs, DNS Logs, System Logs, atau Threat Intelligence Feed. Kategori ini yang nentuin hipotesis default paling relevan di Module 5.5 (mis. Authentication Logs → hipotesis awal seputar credential abuse/brute force)
- **ECS gap analysis** — per field, tandai apakah sudah sesuai konvensi ECS (`source.ip`, `user.name`, dst) atau masih nama vendor asli. Untuk field yang belum ECS, urutan pengecekan:
  1. Cek dulu apakah vendor/produk itu punya **official Elastic integration** (katalog Fleet, repo `elastic/integrations` yang di-clone lokal) — kalau ada, biasanya lebih cepat pasang/rapikan integration resminya daripada bangun mapping custom. Fortinet FortiGate, Cloudflare, dan CyberArk — tiga dari log source yang biasa dipegang — semuanya sudah punya integration resmi dengan ingest pipeline ECS siap pakai
  2. Kalau tidak ada integration resmi (log proprietary/custom app), baru generate saran mapping heuristik sendiri berdasarkan entity recognition di atas, sebagai bagian dari log fingerprint

### 5.3 Feasibility Matching Engine
Dua sumber matching, jalan paralel:

**a. Sigma corpus (eksternal, open-source, offline)**
Cocokkan fingerprint (kategori/produk/service) ke `logsource` di rule Sigma yang sudah di-clone lokal. Kalau field yang dibutuhkan rule Sigma tersebut ada di raw log, jadi kandidat. Mapping MITRE otomatis didapat dari tag rule Sigma-nya (`attack.txxxx`), tidak perlu dipetakan manual.

**b. Taxonomy internal (dikurasi tim, tumbuh seiring project)**
Untuk log source yang tidak ada di korpus Sigma — biasanya log aplikasi proprietary, custom API, atau vendor niche. Ini perlu dibangun manual dari pengalaman tim, persis seperti taxonomy 15-kategori attack pattern yang sudah dibuat untuk Cloudflare WAF. Setiap project baru yang tidak match ke Sigma, hasil analisis manual analyst-nya idealnya di-encode balik jadi entry taxonomy baru — jadi engine ini makin pintar per project, bukan statis.

Output modul ini: list `MatchCandidate` dengan source (sigma/internal), rule reference, confidence, dan mapped MITRE technique(s).

### 5.4 Rule Type Classifier (Elastic)
Begitu ada kandidat match, tentukan tipe rule Elastic yang paling sesuai:

| Kondisi | Tipe Rule Elastic | Alasan |
|---|---|---|
| Field-match sederhana, cukup 1 event | Custom Query (KQL/Lucene) | Kasus paling umum, kompleksitas rendah |
| Butuh urutan/sequence event (proses A → koneksi network B dalam waktu tertentu) | EQL (Event Correlation) | Didesain khusus untuk time-ordered event relationship |
| Butuh hitung volume/frekuensi (mis. banyak failed login dalam window waktu) | Threshold | Native untuk agregasi count per field |
| Butuh agregasi/transformasi kompleks (STATS...BY lalu filter hasil kalkulasi) | ES\|QL | Pipeline query, bisa hitung field baru lalu filter hasilnya |
| Field mengandung entity yang match-able ke threat intel (IP/domain/hash) | Indicator Match | Cocok untuk matching ke indicator index |
| Deteksi "baru pertama kali muncul" (user baru, proses baru, device baru) | New Terms | Purpose-built untuk first-seen detection |
| Butuh baseline adaptif tanpa threshold manual, volume historis cukup panjang | Machine Learning | Perlu ML job aktif + volume data historis memadai |

Kalau kandidat cocok ke lebih dari satu tipe, urutkan berdasarkan kompleksitas paling rendah dulu (custom query di atas EQL/ES\|QL) — konsisten dengan prinsip "pakai tipe paling simpel yang cukup."

Pemetaan ini juga sejalan dengan kategori teknik analisis threat hunting yang lebih luas: EQL ≈ Behavioral Analysis (deviasi pola perilaku), Threshold/ES\|QL ≈ Trend & Statistical Analysis (agregasi dari waktu ke waktu), Indicator Match ≈ Threat Intelligence Correlation, New Terms ≈ Anomaly Detection (baseline deviation), Machine Learning ≈ Statistical and Machine Learning Analysis. Bukan kebetulan — rule type di Elastic memang dirancang untuk mengoperasionalkan teknik-teknik ini.

### 5.5 Hypothesis & Validation Module (jalur NO MATCH)
Struktur hipotesis pakai ABLE (dipakai di kerangka threat hunting modern buat scoping hunt), proses validasinya diadaptasi dari langkah validasi threat hunting standar — diterapkan ke pertanyaan "apakah datanya mendukung untuk dibikin rule", bukan "apakah ini serangan nyata" (karena engine kerja dari sample statis, bukan live hunting):

1. **Hypothesis (format ABLE)**:
   - *Actor* — tipe threat actor/kategori serangan yang relevan buat log ini
   - *Behavior* — perilaku/TTP spesifik yang mau dideteksi, idealnya dengan MITRE technique ID
   - *Location* — log source/kategori data (dari klasifikasi di 5.2) tempat behavior ini kemungkinan muncul
   - *Evidence* — field atau pola spesifik yang dibutuhkan untuk mengonfirmasi behavior tersebut
2. **Validasi**, mengikuti urutan reassess → baseline → correlate → filter → document:
   - **Reassess data & patterns** — field yang disebut di Evidence beneran ada di raw log? (setara field completeness)
   - **Confirm with baselines** — cardinality/distribusi value-nya cukup untuk bedain kondisi normal vs anomali? (relevan kalau Behavior butuh baseline, mis. untuk New Terms/ML)
   - **Correlate with local threat intel** — Behavior dengan MITRE ID-nya itu match ke pola di korpus Sigma atau taxonomy internal?
   - **Contextual filtering** — granularitas timestamp, volume historis, dan field korelasi (session/entity ID) cukup untuk rule type yang diimplikasikan Behavior-nya?
   - **Document & report** — semua hasil check di atas, lolos atau gagal, dicatat sebagai bagian output — bukan cuma kesimpulan akhir
3. **Verdict** — reject, dengan reasoning ringkas dari check yang gagal
4. **Rekomendasi remediasi** — field/log source spesifik (bagian Location & Evidence yang belum terpenuhi) yang perlu ditambah, langsung jadi requirement onboarding di implementation plan, bukan cuma catatan tuning di masa depan

Output modul ini jadi **rejection report**, bukan dead-end — analyst tetap dapat titik awal untuk investigasi manual.

### 5.6 Prediction & Backtest Engine (jalur MATCH)
Sebelum rule benar-benar dibuat di Kibana:

- **Backtest** — jalankan logic rule kandidat terhadap raw log sample yang di-input, hitung berapa kali logic tersebut match
- **Ekstrapolasi volume** — proyeksikan ke estimasi volume produksi (butuh estimasi log rate dari klien, atau dihitung dari time-range sample)
- **Noise estimation** — kalau proporsi match terlalu tinggi relatif ke total event, flag sebagai "berpotensi noisy, butuh tuning tambahan sebelum live"
- **Confidence tier** — High / Medium / Low, kombinasi dari confidence matching (5.3), kelengkapan field, dan hasil backtest

*Catatan untuk fase lanjutan (bukan MVP):* kalau nanti mau lebih rigorous, ada pola dari komunitas Sigma yang mengintegrasikan simulasi Atomic Red Team untuk generate telemetry sintetis dan memvalidasi apakah rule benar-benar fire terhadap teknik yang ditarget. Bisa jadi referensi kalau prediction engine ini mau dikembangkan lebih jauh dari sekadar backtest terhadap sample statis.

### 5.7 Runbook Generator
Auto-generate dokumen per kandidat rule (format markdown, siap disesuaikan ke template runbook tim yang sudah ada):

- Nama rule, objective, MITRE mapping, index/data source yang dibutuhkan, field dependencies
- Tipe rule + draft query/logic (dari hasil convert Sigma via pySigma, atau template internal)
- Kondisi trigger yang diharapkan, pertimbangan false positive
- Hasil prediction/backtest
- Template langkah investigasi untuk analyst yang nanti terima alert

Untuk kandidat yang reject di 5.5, output-nya adalah rejection report, bukan runbook.

### 5.8 Human Review Checkpoint
Setiap output — baik runbook maupun rejection report — masuk antrian review analyst sebelum:

- Rule benar-benar dibuat di Kibana, atau
- Rejection report ditutup/diteruskan sebagai request field tambahan ke klien

## 6. Tech Stack yang Direkomendasikan

| Komponen | Pilihan |
|---|---|
| Bahasa utama | Python (ekosistem data + tooling Sigma paling matang) |
| Profiling data | pandas |
| Matching & konversi rule | pySigma + sigma-cli + pySigma-backend-elasticsearch |
| Korpus rule | Clone lokal SigmaHQ/sigma (offline, refresh berkala) |
| Referensi ECS mapping | Clone lokal `elastic/integrations` (katalog integration resmi + ingest pipeline ECS per vendor, offline, refresh berkala) |
| Metadata teknik | Dataset MITRE ATT&CK (STIX, didownload sekali, disimpan lokal) |
| Taxonomy internal & histori matching | SQLite atau file YAML terstruktur |
| Output | Markdown runbook; opsional lanjut push ke Kibana lewat Detection Rules API (tahap lanjut, tetap manual-trigger bukan auto-deploy) |

Semua komponen di atas jalan tanpa koneksi keluar setelah korpus/dataset awal didownload — cocok untuk lingkungan air-gapped.

## 7. Skeleton Struktur (ilustratif)

```python
# --- struktur inti, bukan implementasi final ---

class FieldProfile:
    field_name: str
    dtype: str
    cardinality: int
    null_rate: float
    entity_type: str | None  # ip, domain, hash, user, port, url, dst

class LogFingerprint:
    profiles: list[FieldProfile]
    inferred_category: str | None   # analog ke logsource.category Sigma
    inferred_product: str | None    # analog ke logsource.product Sigma

class MatchCandidate:
    source: str            # "sigma" | "internal_taxonomy"
    rule_ref: str
    confidence: float
    mitre_techniques: list[str]

class Hypothesis:
    actor: str        # tipe threat actor/kategori serangan
    behavior: str     # TTP spesifik, idealnya dengan MITRE technique ID
    location: str     # log source/kategori data, dari LogFingerprint
    evidence: str     # field/pola yang dibutuhkan untuk konfirmasi

class HypothesisReport:
    hypothesis: Hypothesis
    checks: list[tuple[str, bool, str]]  # (nama_check, passed, detail)
    verdict: str            # "rejected"
    remediation: str | None

class PredictionResult:
    estimated_alert_volume: float
    confidence_tier: str    # High | Medium | Low
    notes: str


def process_log_sample(raw_log_path: str):
    records = ingest_and_normalize(raw_log_path)
    fingerprint = profile_fields(records)

    candidates = (
        match_against_sigma(fingerprint)
        + match_against_internal_taxonomy(fingerprint)
    )

    if candidates:
        best = select_best_candidate(candidates)
        rule_type = classify_elastic_rule_type(best, fingerprint)
        prediction = backtest_rule(best, records)
        return generate_runbook(best, rule_type, prediction)

    hypothesis = build_hypothesis(fingerprint)
    validation = validate_hypothesis(hypothesis, fingerprint)
    return generate_rejection_report(hypothesis, validation)
```

## 8. Local Execution & UI Layer

### 8.1 Launcher
- `run.bat` sebagai entry point, tapi cuma wrapper tipis: aktivasi venv (kalau pakai), lalu panggil `python -m engine.serve`. Jangan taruh logic apa pun langsung di batch script — susah di-maintain begitu lebih dari beberapa baris
- Setelah proses server jalan, launcher otomatis buka browser ke `http://127.0.0.1:<port>` (lewat `start` di .bat, atau modul `webbrowser` di Python) — supaya beneran "double-click, langsung kepakai," bukan double-click lalu masih harus buka browser manual
- Cek port belum dipakai sebelum start; kalau instance lain masih jalan, langsung buka browser ke instance yang ada daripada gagal start kedua kalinya

### 8.2 Local web server
- Rekomendasi **FastAPI + Uvicorn** — dukungan async-nya pas dengan prinsip "batch/asynchronous" di Section 3: job profiling/matching bisa jalan sebagai background task, UI tinggal polling status, user bisa pindah kerjaan lain sambil nunggu
- **Bind ke `127.0.0.1` saja, jangan `0.0.0.0`** — ini yang menegakkan constraint "fully offline/confidential" di level network, bukan cuma niat baik. Bind ke `0.0.0.0` berarti device lain di jaringan yang sama berpotensi bisa akses tool ini dan lihat raw log klien
- Tidak butuh auth/login — localhost-only dan single-user, auth cuma nambah kompleksitas tanpa manfaat nyata di skenario ini

### 8.3 Frontend
- Rekomendasi **server-rendered (Jinja2) + htmx**, bukan SPA (React/Vue dengan build pipeline) — ini tool internal untuk satu-dua pemakai, bukan produk yang butuh arsitektur frontend yang scalable. htmx pas untuk pola "upload → server proses → tampilkan sebagian halaman baru" tanpa nulis JS API-calling manual
- Drag-and-drop upload pakai HTML5 File API standar — sudah well-solved, tidak perlu library tambahan

### 8.4 Alur halaman yang direkomendasikan
1. **Upload** — drag-and-drop raw log (CSV/JSON/dll), opsional field hint (mis. "vendor/product kalau tahu" — kepakai di ECS gap analysis 5.2)
2. **Struktur & Fingerprint** — hasil Module 5.1-5.2 ditampilkan: tabel field, entity type per field, status ECS gap, klasifikasi tipe data. Bagian ini yang bikin user bisa "lihat dulu" sebelum lanjut
3. **Hasil Matching** — kalau MATCH: kandidat rule + tipe rule + MITRE mapping + hasil prediction/backtest, dengan tombol **Generate Runbook**. Kalau NO MATCH: rejection report format ABLE beserta hasil tiap langkah validasi
4. **Riwayat** — list run sebelumnya, supaya tidak hilang kalau server di-restart

### 8.5 Job & state
- Job history dan hasil run disimpan di SQLite yang sama seperti taxonomy internal (Section 6) — satu file lokal, gampang backup/pindah
- Untuk background task, cukup pakai `BackgroundTasks` bawaan FastAPI di kasus umum. Kalau nanti butuh job yang survive restart server (proses lama, ditinggal semalaman), baru pertimbangkan queue ringan seperti `huey` dengan SQLite backend — jangan langsung loncat ke Celery+Redis, itu overkill untuk single-user local tool

### 8.6 Packaging (belakangan, bukan sekarang)
- Selama masih fase build/iterasi, venv + `run.bat` sudah cukup
- Kalau engine-nya sudah stabil dan mau didistribusikan ke rekan lain tanpa mereka perlu setup Python, baru pertimbangkan bundling jadi single executable (PyInstaller) — tapi ini belakangan, jangan investasi waktu di situ selagi logic intinya masih berubah-ubah

## 9. Roadmap Eksekusi Bertahap

**Fase 0 — Seeding knowledge base**
- Clone korpus SigmaHQ, setup pySigma + backend Elastic
- Clone katalog `elastic/integrations` sebagai referensi ECS mapping resmi per vendor
- Mulai isi taxonomy internal dari pola yang sudah ada (mis. taxonomy Cloudflare WAF) sebagai contoh awal struktur
- *Selesai kalau:* satu log sample bisa di-profile dan dicocokkan manual ke minimal 1 Sigma rule sebagai proof-of-concept

**Fase 1 — MVP matching**
- Modul 1-3 (ingestion, profiling, matching ke Sigma saja dulu, belum taxonomy internal)
- Output masih sederhana: list kandidat match + MITRE mapping, belum runbook lengkap
- *Selesai kalau:* bisa diuji ke 3-5 log sample project lama, hasil matching masuk akal secara manual review

**Fase 2 — Hypothesis & rejection module**
- Modul 5 lengkap dengan checks
- *Selesai kalau:* log sample yang sengaja "sulit" (field minim) menghasilkan rejection report yang reasoning-nya masuk akal, bukan cuma "no match"

**Fase 3 — Rule type classifier + taxonomy internal**
- Modul 3b (taxonomy internal) dan modul 4
- *Selesai kalau:* rekomendasi tipe rule untuk kandidat match konsisten dengan keputusan manual yang biasa diambil analyst

**Fase 4 — Prediction & backtest**
- Modul 6
- *Selesai kalau:* estimasi alert volume dari backtest tidak meleset jauh dari kondisi live rule serupa yang sudah pernah dibuat manual

**Fase 5 — Runbook generator + integrasi workflow project**
- Modul 7-8, dan jadikan bagian standar dari kickoff project IMS baru. Di fase ini engine masih dijalankan lewat CLI/script — validasi logic intinya dulu sebelum investasi waktu di UI
- *Selesai kalau:* dipakai di minimal 1 project real dari awal sampai handover

**Fase 6 — Local web UI**
- Bungkus engine yang sudah tervalidasi dengan layer di Section 8: launcher `.bat`, server FastAPI lokal, halaman upload/struktur/hasil/riwayat
- *Selesai kalau:* rekan satu tim bisa pakai tanpa perlu tahu cara menjalankan script Python-nya — cukup double-click launcher

## 10. Risiko & Catatan Penting

- **Coverage gap** — log proprietary/custom app kemungkinan besar tidak ada di korpus Sigma; taxonomy internal harus jadi prioritas, bukan afterthought
- **Overhead maintenance** — knowledge base butuh dirawat terus; kalau tidak, akurasi matching akan menurun seiring waktu
- **"No match" ≠ "tidak bisa dideteksi"** — pastikan output engine selalu framing ini dengan jelas supaya tidak menimbulkan false sense of completeness
- **Ceiling akurasi heuristic** — sistem ini alat bantu triase, bukan pengganti keahlian analyst, terutama untuk log source yang benar-benar baru/aneh
- **Validasi awal wajib manual** — sebelum dipakai di project real, hasil matching & rule-type classifier harus divalidasi dulu terhadap keputusan yang pernah diambil manual, supaya ketahuan kalau logic classifier-nya perlu dikoreksi
- **Remediation di luar scope** — engine berhenti di rekomendasi rule/dokumentasi. Containment, eradication, dan recovery insiden tetap proses IR terpisah yang tidak disentuh engine ini

---

*Referensi konsep: Sigma / SigmaHQ (korpus rule terbuka), pySigma (library konversi), MITRE ATT&CK (framework teknik), dokumentasi tipe rule Elastic Security, kerangka PEAK & ABLE (structuring hipotesis threat hunting), dan dokumen metodologi threat hunting yang disusun sendiri.*
