# Agent Guidelines: Pantau Server

Berkas ini memandu seluruh asisten AI yang bekerja pada proyek **Pantau Server** (`/home/bos/rj45`).

## 1. Domain Docs (Single Source of Truth)

Seluruh definisi istilah domain, arsitektur sistem, aturan antarmuka visual, dan batas kewenangan diatur secara terpusat pada:
- [`CONTEXT.md`](file:///home/bos/rj45/CONTEXT.md): Kamus domain tunggal (*Ubiquitous Language*), prinsip rekayasa sistemik, spesifikasi baku UI/UX, dan protokol alur kerja.
- [`GEMINI.md`](file:///home/bos/rj45/GEMINI.md): Aturan teknis pelengkap dan ceklis sistem pra-lapor.

## 2. Standar Operasional Prosedur (SOP) Rilis

Seluruh alur peningkatan versi SemVer, kompilasi sintaksis, restart daemon, rilis GitHub, dan verifikasi lapangan 100% armada wajib menggunakan:
- Skrip otomasi: [`tools/sop_release.py`](file:///home/bos/rj45/tools/sop_release.py)
- Panduan skill: [`SKILL.md`](file:///home/bos/rj45/.agents/skills/sop-pantau/SKILL.md)

## 3. Disiplin Rekayasa Mutlak

1. **Proteksi Dasbor**: Berkas `server/templates/dashboard.html` dilarang disentuh tanpa instruksi khusus.
2. **Paginasi Universal**: $\le 10$ baris disembunyikan otomatis (`display: none !important`), $> 10$ baris ditampilkan.
3. **Standarisasi Kolom**: Header wajib bernama "Tindakan" (kapitalisasi diawali huruf besar). Dropdown `Aksi ▾` jika $> 2$ opsi aksi; tombol inline sejajar jika $\le 2$ opsi aksi.
4. **Kejujuran Data (Zero-Fake Data)**: Hanya simpan dan tampilkan data terukur fisik dari kernel. Dilarang mengarang atribusi atau memalsukan status.
5. **Verifikasi Lapangan Nyata**: Wajib membuktikan 100% armada aktif melapor pada versi baru via kueri database sebelum melapor selesai kepada operator.
