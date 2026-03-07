# NetSentinel

Gerçek zamanlı ağ güvenliği izleme ve saldırı tespit sistemi.

## Özellikler
- Canlı paket yakalama (`scapy`) ile temel ağ olayları üretme
- JSONL event ingest desteği
- Threat intelligence (IOC) eşleştirme
- Kural tabanlı tespit:
  - Port scan
  - Şüpheli DNS sorgusu / yüksek entropy
  - Brute force benzeri login denemeleri (log/event bazlı)
- Risk skoru ve alarm üretimi
- Basit dashboard + WebSocket canlı akış
- REST API

## Uyarı
Bu proje **yalnızca yetkili olduğun ağlarda ve savunma amaçlı** kullanılmalıdır.

## Kurulum
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Çalıştırma
```bash
uvicorn app.main:app --reload
```

Tarayıcı:
- Dashboard: http://127.0.0.1:8000/
- API docs: http://127.0.0.1:8000/docs

## Canlı Sniffer Başlatma
Varsayılan olarak loopback dışındaki ilk uygun arayüzü seçmeye çalışır.

```bash
curl -X POST http://127.0.0.1:8000/api/sniffer/start
```

Belirli arayüz:
```bash
curl -X POST "http://127.0.0.1:8000/api/sniffer/start?iface=eth0"
```

Durdurma:
```bash
curl -X POST http://127.0.0.1:8000/api/sniffer/stop
```

## JSONL Event Ingest
Satır başına bir JSON obje olacak şekilde event dosyası yükleyebilirsin.

Örnek event:
```json
{"timestamp":"2026-03-07T15:10:00Z","src_ip":"10.0.0.5","dst_ip":"8.8.8.8","dst_port":53,"protocol":"udp","event_type":"dns_query","query":"example.com","source":"custom"}
```

Yükleme:
```bash
curl -F "file=@data/sample_events.jsonl" http://127.0.0.1:8000/api/ingest/jsonl
```

## Threat Intel Dosyası
`data/threat_intel.csv`

Kolonlar:
- type: `ip` veya `domain`
- value
- severity: `low|medium|high|critical`
- source
- note

## Proje Yapısı
```text
netsentinel/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── models.py
│   ├── store.py
│   ├── utils.py
│   ├── threat_intel.py
│   ├── detectors.py
│   ├── collector.py
│   └── static/
│       └── index.html
├── data/
│   ├── threat_intel.csv
│   └── sample_events.jsonl
├── scripts/
│   └── simulate_events.py
├── requirements.txt
└── README.md
```


## Yeni dashboard özellikleri
- Modern glassmorphism arayüz
- Threat/risk skoru göstergesi
- Protokol donut görünümü
- Severity dağılım çubukları
- Top source IP ve top hedef port panelleri
- Global arama/filter
- JSON export ve JSONL upload
- WebSocket ile canlı alarm güncellemesi
