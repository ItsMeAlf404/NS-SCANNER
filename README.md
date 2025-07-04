🛡 DNS & Nameserver Scanner

Alat sederhana untuk melakukan pemindaian domain secara massal dan mendeteksi:
- Nameserver (NS)
- Apakah NS bisa di-resolve (aktif atau mati)
- Status domain NS (REGISTERED / AVAILABLE)
- MX Record dan A Record

Program ini sangat cocok digunakan untuk:
- Audit keamanan domain
- Deteksi potensi takeover
- Pengumpulan data DNS

Cara Instalasi :
- pip install dnspython colorama
- python scanns.py

*Setelah scanning selesai , output akan memberikan/menyimpan otomatis hasil ke .csv
