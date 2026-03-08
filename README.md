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
- Docker ve Docker Compose ile deploy uyumu
- Runtime snapshot persistence (`data/runtime/runtime_snapshot.json`)

## Uyarı
Bu proje **yalnızca yetkili olduğun ağlarda ve savunma amaçlı** kullanılmalıdır.

## Lokal geliştirme
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Tarayıcı:
- Dashboard: http://127.0.0.1:8000/
- API docs: http://127.0.0.1:8000/docs

## Docker ile ayağa kaldırma
### Tek container
```bash
docker build -t netsentinel .
docker run -d \
  --name netsentinel \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  --restart unless-stopped \
  netsentinel
```

### Docker Compose
```bash
docker compose up -d --build
```

## Sunucu deploy mantığı
Üretim için mantık şu:
- `./data` volume olarak mount edilir
- threat intel CSV burada tutulur
- runtime snapshot burada saklanır
- container restart olunca son snapshot geri yüklenir
- reverse proxy (Nginx/Caddy/Traefik) ile 80/443'e alınır

### Önerilen reverse proxy
- Nginx
- Caddy
- Traefik

### Basit Nginx örneği
```nginx
server {
    listen 80;
    server_name senin-domainin.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws {
        proxy_pass http://127.0.0.1:8000/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

## Sniffer container notu
Sunucuda canlı trafik sniff etmek istiyorsan normal web container yeterli olmaz.
Bunun için:
- `network_mode: host`
- `cap_add: NET_ADMIN`
- `cap_add: NET_RAW`

gerekir. Bu yüzden compose dosyasında ayrı bir `netsentinel-sniffer` servisi profille eklendi.

Başlatmak için:
```bash
docker compose --profile sniffer up -d --build
```

Ama gerçek konuşalım: sniffing işi prod sunucuda yanlış kurarsan tadı kaçar. Önce log ingest ile başlamak daha güvenli.

## JSONL Event Ingest
Örnek yükleme:
```bash
curl -F "file=@data/sample_events.jsonl" http://127.0.0.1:8000/api/ingest/jsonl
```

## Threat Intel dosyası
`data/threat_intel.csv`

Kolonlar:
- type: `ip` veya `domain`
- value
- severity: `low|medium|high|critical`
- source
- note

IOC dosyasını güncelledikten sonra reload:
```bash
curl -X POST http://127.0.0.1:8000/api/intel/reload
```

## Sağlık kontrolü
```bash
curl http://127.0.0.1:8000/api/health
```

## Dosya yapısı
```text
netsentinel/
├── app/
├── data/
│   ├── runtime/
│   │   └── runtime_snapshot.json
│   ├── threat_intel.csv
│   └── sample_events.jsonl
├── deploy/
│   └── entrypoint.sh
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── .env.example
├── requirements.txt
└── README.md
```

## Hızlı deploy akışı
```bash
git clone <repo>
cd netsentinel
cp .env.example .env
docker compose up -d --build
```

Sonra:
- domain'i reverse proxy'ye bağla
- HTTPS aç
- `data/threat_intel.csv` dosyanı güncelle
- `/api/intel/reload` vur

## Sonraki upgrade için mantıklı şeyler
- PostgreSQL / OpenSearch
- kullanıcı girişi
- JWT auth
- role-based access
- çoklu sensor
- ayrı worker servisleri
- Redis queue
- alert notification (Discord, Slack, mail)
