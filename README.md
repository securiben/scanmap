# 📡 SCANMAP

Smart Nmap wrapper that groups targets by service and runs NSE in bulk for ultra-fast network reconnaissance.

This tool **changes the way Nmap is executed**:

> ❌ Not scanning per IP  
> ✅ Bulk scanning per **service**

Results:
- Much faster execution
- Cleaner output
- Minimal noise (no broadcast / brute / spam)
- Report-ready results

---

## 🚀 Why this tool exists

A common problem when running Nmap on large subnets:

```
nmap -sCV 10.10.0.0/24
```


➡️ Extremely slow  
➡️ Too much unnecessary output  
➡️ Nmap gets executed hundreds of times

SCANMAP changes the workflow into:

**Host discovery → Port discovery → Service detection → Group IPs by service → Run NSE in bulk per service**

---

## ⚙️ Features

- Automatic host discovery
- Top 1000 port discovery
- Automatic service parsing
- Bulk NSE execution based on service
- No brute force
- No broadcast noise
- Supports: subnet / single IP / file list

---

## 📦 Requirements

- `nmap`
- `httpx` (optional, for web probing)

---

## 🛠️ Usage

```
./scan.sh 10.10.0.0/24
./scan.sh 10.10.0.5
./scan.sh targets.txt
```
## Preview
<img width="513" height="394" alt="image" src="https://github.com/user-attachments/assets/fc2ad4fa-6edc-4384-96c7-b3d97a3a81a6" />

## 📄 License
Free to use for educational & security assessment purposes.
