# Konstruksi S-box 8-bit dengan Optimasi (GA/SA) + Enkripsi Citra AES

Proyek UAS Kriptografi. Membangun S-box 8-bit menggunakan algoritma optimasi, menguji kekuatannya,
memakainya pada AES-128 (mode CBC/CTR) untuk mengenkripsi citra, lalu menganalisis hasilnya
dalam aplikasi Streamlit.

Demo: _isi dengan link Streamlit Cloud_

## Fitur

- **Konstruksi S-box**
  - *Hybrid GA + SA*: mencari matriks affine `A` (dan konstanta `c`) pada `S(x) = A · inverse(x) ⊕ c`
    di GF(2^8), dengan pilihan polinomial irreducible. Hasil selalu bijektif dan balance.
  - *SA permutasi murni 0-255*: pembanding. Umumnya hanya mencapai NL sekitar 96-106.
- **Pengujian S-box**: Balance, Bijektif, NL, SAC, BIC-NL, BIC-SAC, LAP, DAP, fixed point,
  nilai `S` dan `SV` (Eq. 9 dan 20 paper), perbandingan dengan S-box AES dan S-box44 paper.
- **AES-128 custom**: S-box dan inverse S-box dapat diganti, mode CBC (PKCS7) dan CTR.
- **Analisis citra**: entropi, NPCR, UACI (ubah 1 piksel dan ubah 1 bit kunci), chi-square, histogram,
  verifikasi dekripsi.

## Struktur

```
sbox_uas/
├── app.py              # aplikasi Streamlit (3 tab)
├── sbox_core.py        # konstruksi S-box (GA/SA) dan fungsi penilai
├── aes_custom.py       # AES-128 dengan S-box custom, CBC dan CTR
├── image_analysis.py   # entropi, NPCR, UACI, histogram
├── presets.py          # S-box44 dari paper Alamsyah et al.
└── requirements.txt
```

## Menjalankan

Python 3.10+ disarankan. Di Ubuntu/WSL gunakan virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Aplikasi terbuka di `http://localhost:8501`.

## Cara pakai

1. **Konstruksi S-box**: pilih algoritma dan parameter, klik *Jalankan optimasi*. Bisa juga memakai
   S-box AES atau S-box44 paper sebagai preset.
2. **Pengujian S-box**: lihat tabel 16x16, hasil uji lengkap, matriks SAC/BIC-SAC, lalu unduh S-box (CSV/JSON).
3. **Enkripsi citra**: unggah citra, pilih mode CBC/CTR dan passphrase, klik *Enkripsi*.
   Hasil dibandingkan dengan AES standar.

## Hasil pengujian

Validasi penilai terhadap nilai pada paper rujukan:

| S-box | NL | SAC | BIC-NL | BIC-SAC | LAP | DAP | SV |
|---|---|---|---|---|---|---|---|
| AES | 112 | 0,50488 | 112 | 0,50460 | 0,0625 | 0,015625 | 16,0095 |
| S-box44 (paper) | 112 | 0,50073 | 112 | 0,50237 | 0,0625 | 0,015625 | 16,0031 |

Hasil S-box hasil optimasi kelompok dan analisis citra: _isi setelah S-box final ditetapkan_.

Catatan metodologi:

- SAC dan BIC-SAC dilaporkan sebagai rata-rata matriks (seperti paper). Rata-rata bisa mendekati 0,5 karena
  deviasi antar-sel saling meniadakan, sehingga aplikasi juga menampilkan deviasi maksimum per sel.
- Karena S-box hybrid diturunkan dari inverse GF(2^8), NL/LAP/DAP otomatis 112 / 0,0625 / 0,015625.
  Yang dioptimalkan adalah SAC dan BIC-SAC.
- Pada mode CTR, mengubah 1 piksel hanya mengubah 1 byte cipher (NPCR sekitar 0%). Ini sifat mode stream.
  Sensitivitas terhadap kunci tetap sekitar 99,6%.
- Kunci diturunkan dari passphrase dengan SHA-256 dan IV dibuat acak per enkripsi. Proyek ini untuk
  keperluan akademik, bukan untuk melindungi data sungguhan.

## Verifikasi implementasi

- AES custom dengan S-box standar cocok dengan vektor uji FIPS-197
  (kunci `000102...0f`, plaintext `00112233...ff` menghasilkan `69c4e0d86a7b0430d8cdb78070b4c55a`).
- Round-trip enkripsi-dekripsi CBC dan CTR kembali ke data asli.

## Referensi

- Alamsyah et al., *AES S-box modification uses affine matrices exploration for increased S-box strength*,
  Nonlinear Dynamics 113, 3869-3890 (2025). https://doi.org/10.1007/s11071-024-10414-3
- Daemen, J., Rijmen, V., *The Design of Rijndael*, Springer (2002).

## Tim

| Nama | NIM | Peran |
|---|---|---|
| _isi_ | _isi_ | Konstruksi S-box |
| _isi_ | _isi_ | Pengujian S-box |
| _isi_ | _isi_ | AES dan analisis citra |
| _isi_ | _isi_ | Streamlit dan laporan |
