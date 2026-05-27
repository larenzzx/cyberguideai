# Local Docker Deployment Guide

Use this guide to run CyberGuide AI on an internal Ubuntu server with Docker and PostgreSQL.

## 1. Push The Local Deployment Branch

From your development machine:

```bash
git status
git add .
git commit -m "Add local Docker deployment"
git push origin local
```

This keeps the Docker/local-server deployment changes on the `local` branch.

## 2. Install Docker On Ubuntu

On the Ubuntu server:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin git
sudo systemctl enable docker
sudo systemctl start docker
```

Optional: allow your user to run Docker without `sudo`.

```bash
sudo usermod -aG docker $USER
```

Log out and log back in after running that command.

## 3. Clone The Local Branch

On the Ubuntu server, choose an install folder:

```bash
cd /opt
sudo git clone -b local https://github.com/YOUR-USERNAME/YOUR-REPO.git cyberguideai
sudo chown -R $USER:$USER /opt/cyberguideai
cd /opt/cyberguideai
```

If the repo is already cloned:

```bash
cd /opt/cyberguideai
git fetch origin
git checkout local
git pull origin local
```

## 4. Create The Server Environment File

Copy the Docker env template:

```bash
cp .env.docker.example .env
nano .env
```

Update these values:

```env
SECRET_KEY=use-a-long-random-secret
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1,192.168.1.50,cyberguide.local
CSRF_TRUSTED_ORIGINS=http://192.168.1.50:8000,http://cyberguide.local:8000
APP_PORT=8000
POSTGRES_DB=cyberguideai
POSTGRES_USER=cyberguideai
POSTGRES_PASSWORD=use-a-strong-local-db-password
GROQ_API_KEY=your-groq-key
VIRUSTOTAL_API_KEY=your-virustotal-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
OTX_API_KEY=your-otx-key
```

Replace `192.168.1.50` with the Ubuntu server IP address.

If you only want access by IP, you can remove `cyberguide.local`.

## 5. Build And Start The App

```bash
docker compose up -d --build
```

Check containers:

```bash
docker compose ps
```

Watch logs:

```bash
docker compose logs -f web
```

Open the app from another machine on the same network:

```text
http://SERVER-IP:8000
```

Example:

```text
http://192.168.1.50:8000
```

## 6. Create The First Admin User

```bash
docker compose exec web python manage.py createsuperuser
```

Then log in:

```text
http://SERVER-IP:8000/login/
```

## 7. Updating The Local Server Later

After pushing new changes to the `local` branch:

```bash
cd /opt/cyberguideai
git checkout local
git pull origin local
docker compose up -d --build
```

The PostgreSQL data stays in the Docker volume named `postgres_data`.

## 8. Useful Commands

Stop the app:

```bash
docker compose down
```

Restart:

```bash
docker compose restart
```

View logs:

```bash
docker compose logs -f
```

Run migrations manually:

```bash
docker compose exec web python manage.py migrate
```

Open Django shell:

```bash
docker compose exec web python manage.py shell
```

## 9. Optional Local DNS Name

To use `http://cyberguide.local:8000`, add a DNS record in your router or internal DNS server that points `cyberguide.local` to your Ubuntu server IP.

For a single Windows client, you can add this to:

```text
C:\Windows\System32\drivers\etc\hosts
```

Example:

```text
192.168.1.50 cyberguide.local
```
