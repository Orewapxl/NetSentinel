# NetSentinel

Docker ve Coolify uyumlu gerçek zamanlı ağ güvenliği izleme MVP'si.

## Lokal çalıştırma

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --proxy-headers --forwarded-allow-ips='*'
```

## Docker

```bash
docker compose up -d --build
```

## Coolify

- Build Pack: `Docker Compose`
- Base Directory: `/`
- Compose file: `docker-compose.yml`
- Port mapping kullanma; Coolify proxy kullansın.
- Domain ekle ve app'i root domaine yayınla.
- Gerekirse env olarak `NETSENTINEL_ROOT_PATH` ver.

### Redirect loop fix

Bu sürümde:
- app içinde HTTPS redirect yok
- container `0.0.0.0:8000` dinliyor
- uvicorn proxy header destekli çalışıyor
- compose `ports` yerine `expose` kullanıyor

## Health

```bash
curl http://127.0.0.1:8000/api/health
```
