# 📡 SCANMAP

Automation wrapper di atas **Nmap** untuk mempercepat proses reconnaissance & enumeration pada VAPT / internal pentest.

Tool ini **mengubah cara Nmap dijalankan**:

> ❌ Bukan scan per IP  
> ✅ Scan massal per **service**

Hasilnya:
- Jauh lebih cepat
- Output lebih bersih
- Minim noise (tanpa broadcast / brute / spam)
- Siap jadi bahan report

---

## 🚀 Kenapa tool ini dibuat?

Masalah umum saat pakai Nmap di subnet besar:
```
nmap -sCV 10.10.0.0/24
```

➡️ Sangat lama  
➡️ Banyak output tidak perlu  
➡️ Nmap dipanggil ratusan kali

Tool ini mengubah alur menjadi:

Host discovery → Port discovery → Deteksi service → Kelompokkan IP berdasarkan service → Jalankan NSE massal per service

---

## ⚙️ Fitur

- Host discovery otomatis
- Top 1000 port discovery
- Parsing service otomatis
- Bulk NSE berdasarkan service
- Tanpa brute force
- Tanpa broadcast noise
- Support: subnet / single IP / file list

---

## 📦 Requirement

- `nmap`
- `httpx` (opsional, untuk web probing)

---

## 🛠️ Cara Pakai

```
./scan.sh 10.10.0.0/24
./scan.sh 10.10.0.5
./scan.sh targets.txt
```

## 📄 License
Free to use for educational & security assessment purposes.
