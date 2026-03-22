#!/bin/bash
# Populate sacrificial VM with realistic users, services, fake files, and honeytokens
# Makes the honeypot look like a sloppy production server

set -e

echo "=== Populating Honeypot with Decoys ==="

# ---------------------------------------------------------------------------
# Users — mix of devs, ops, service accounts
# ---------------------------------------------------------------------------
echo "[+] Creating user accounts..."

declare -A USERS=(
    [jchen]="Jason Chen"
    [srao]="Sunita Rao"
    [mkovacs]="Milan Kovacs"
    [deploy]="Deploy Bot"
    [jenkins]="Jenkins CI"
    [gitlab-runner]="GitLab Runner"
    [nagios]="Nagios Monitoring"
    [backup]="Backup Service"
    [webadmin]="Web Administrator"
    [dbadmin]="Database Admin"
    [appuser]="Application Service"
    [devops]="DevOps Team"
    [ftpuser]="FTP Upload"
    [redis]="Redis Service"
    [mongodb]="MongoDB Service"
    [elastic]="Elasticsearch"
    [docker]="Docker Service"
    [ansible]="Ansible Automation"
    [prometheus]="Prometheus Monitoring"
    [www-data]="Web Server"
)

for user in "${!USERS[@]}"; do
    if ! id "$user" &>/dev/null; then
        useradd -m -s /bin/bash -c "${USERS[$user]}" "$user" 2>/dev/null || true
    fi
done

# ---------------------------------------------------------------------------
# SSH keys scattered around (fake but realistic)
# ---------------------------------------------------------------------------
echo "[+] Planting SSH keys..."

for user in jchen srao mkovacs deploy webadmin dbadmin devops; do
    HOME_DIR="/home/$user"
    mkdir -p "$HOME_DIR/.ssh"

    # Generate throwaway keys
    ssh-keygen -t ed25519 -f "$HOME_DIR/.ssh/id_ed25519" -N "" -q 2>/dev/null || true
    ssh-keygen -t rsa -b 2048 -f "$HOME_DIR/.ssh/id_rsa" -N "" -q 2>/dev/null || true

    # Fake known_hosts
    cat > "$HOME_DIR/.ssh/known_hosts" << 'EOF'
10.0.1.50 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKqR3kMwJx7YvO2PqFHzVJxL4m5NrJ0X6vWL+yGh1234
10.0.1.51 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbM9pLdX5zZ3wK8fhYvP0qTt2nM6xR0L+yGh5678
prod-db-01.internal ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxyz...
staging-web-03.internal ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyHere
git.company-internal.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMoreFakeKeys
EOF

    # Fake SSH config
    cat > "$HOME_DIR/.ssh/config" << 'EOF'
Host prod-db-*
    User dbadmin
    IdentityFile ~/.ssh/id_rsa
    Port 22

Host staging-*
    User deploy
    IdentityFile ~/.ssh/id_ed25519
    StrictHostKeyChecking no

Host *.internal
    ProxyJump bastion.company-internal.com
    User svc-deploy

Host bastion
    HostName 203.0.113.50
    User jchen
    Port 2222
EOF

    chown -R "$user:$user" "$HOME_DIR/.ssh" 2>/dev/null || true
    chmod 700 "$HOME_DIR/.ssh"
    chmod 600 "$HOME_DIR/.ssh/"* 2>/dev/null || true
done

# ---------------------------------------------------------------------------
# Bash histories — make it look lived-in
# ---------------------------------------------------------------------------
echo "[+] Planting bash histories..."

cat > /home/jchen/.bash_history << 'EOF'
cd /opt/webapp
git pull origin main
docker-compose up -d
docker logs -f webapp_api_1
tail -f /var/log/nginx/access.log
mysql -u root -p'Pr0d_db_2025!@' -h 10.0.1.50 production_db
mysqldump -u root -p'Pr0d_db_2025!@' -h 10.0.1.50 production_db > /tmp/prod_backup_20260315.sql
scp /tmp/prod_backup_20260315.sql backup@10.0.1.55:/mnt/backups/
kubectl get pods -n production
kubectl logs -f deploy/api-server -n production
ssh deploy@staging-web-03.internal
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.fake_jwt_token" https://api.internal/v1/users
aws s3 ls s3://company-prod-backups/
aws s3 cp s3://company-prod-backups/db-2026-03.tar.gz /tmp/
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
terraform plan -var-file=prod.tfvars
ansible-playbook -i inventory/production deploy-webapp.yml
cat /etc/shadow
sudo cat /etc/shadow
vim /opt/webapp/.env
cat /opt/webapp/config/database.yml
redis-cli -h 10.0.1.52 -a 'R3dis_Pr0d_Pass!'
mongo --host 10.0.1.53 -u admin -p 'M0ng0_Adm1n_2025' --authenticationDatabase admin
EOF

cat > /home/srao/.bash_history << 'EOF'
docker ps
docker exec -it postgres_db psql -U admin
pg_dump -U admin -h localhost production > /tmp/pg_backup.sql
cd /opt/monitoring
vim prometheus.yml
systemctl restart prometheus
grafana-cli admin reset-admin-password Gr4fana_Adm1n!
curl -u admin:Gr4fana_Adm1n! http://localhost:3000/api/datasources
kubectl get secrets -n production
kubectl get secret db-credentials -n production -o jsonpath='{.data.password}' | base64 -d
ssh -L 5432:prod-db-01.internal:5432 bastion
psql -h localhost -p 5432 -U postgres -d production
cat /opt/webapp/config/secrets.yml
openssl req -new -x509 -key /etc/ssl/private/server.key -out /etc/ssl/certs/server.crt
certbot renew --dry-run
EOF

cat > /home/mkovacs/.bash_history << 'EOF'
cd /home/mkovacs/crypto-bot
python3 trading_bot.py --config config.json
cat config.json
vim config.json
python3 -c "from web3 import Web3; w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/a1b2c3d4e5f6'))"
node scripts/check_balance.js
cat .env
export BINANCE_API_KEY=vM3xR7kLp9Qw2nJ5tY8uB4cF6hA0dE1
export BINANCE_SECRET=zX9wV7uT5sR3qP1oN8mL6kJ4hG2fD0c
bitcoin-cli getbalance
bitcoin-cli listunspent
cat /home/mkovacs/.bitcoin/bitcoin.conf
python3 withdraw.py --amount 2.5 --address bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
ssh mkovacs@exchange-api.internal
curl -H "X-MBX-APIKEY: vM3xR7kLp9Qw2nJ5tY8uB4cF6hA0dE1" "https://api.binance.com/api/v3/account"
EOF

cat > /root/.bash_history << 'EOF'
apt update && apt upgrade -y
systemctl status nginx mysql redis-server
tail -f /var/log/syslog
iptables -L -n
netstat -tulpn
cat /etc/shadow
passwd deploy
usermod -aG sudo jchen
vim /etc/nginx/sites-enabled/webapp.conf
certbot certonly --nginx -d api.company-internal.com
mysql -u root -p
mysql -u root -p'r00t_MySQL_2025!!'
redis-cli CONFIG SET requirepass ""
crontab -l
cat /root/scripts/backup.sh
/root/scripts/backup.sh
ssh-copy-id deploy@10.0.1.51
scp /root/.ssh/id_rsa deploy@staging-web-03:/tmp/
chmod 777 /opt/webapp/uploads
docker system prune -af
kubectl delete pod --all -n staging
history | grep password
find / -name "*.pem" -o -name "*.key" 2>/dev/null
EOF

# ---------------------------------------------------------------------------
# Fake application / web configs
# ---------------------------------------------------------------------------
echo "[+] Creating fake application configs..."

mkdir -p /opt/webapp/config /opt/webapp/logs /opt/webapp/uploads /opt/webapp/scripts

cat > /opt/webapp/.env << 'EOF'
# Production Environment — DO NOT COMMIT
NODE_ENV=production
PORT=3000
DB_HOST=10.0.1.50
DB_PORT=3306
DB_NAME=production_db
DB_USER=webapp_prod
DB_PASS=xK9#mP2$vL5nQ8wR
REDIS_URL=redis://:R3dis_Pr0d_Pass!@10.0.1.52:6379
MONGO_URI=mongodb://admin:M0ng0_Adm1n_2025@10.0.1.53:27017/app?authSource=admin
JWT_SECRET=super_secret_jwt_key_do_not_share_2025
API_KEY=sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789
STRIPE_SECRET_KEY=FAKE_HONEYPOT_STRIPE_KEY_NOT_REAL
STRIPE_WEBHOOK_SECRET=whsec_1234567890abcdefghijklmnop
SENDGRID_API_KEY=SG.aBcDeFgHiJkLmNoPqRsT.UvWxYz1234567890abcdefghij
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1
S3_BUCKET=company-prod-uploads
SENTRY_DSN=https://abc123@o456.ingest.sentry.io/789
SLACK_WEBHOOK=https://FAKE-HONEYPOT-SLACK-WEBHOOK-NOT-REAL
EOF

cat > /opt/webapp/config/database.yml << 'EOF'
production:
  adapter: mysql2
  host: 10.0.1.50
  port: 3306
  database: production_db
  username: webapp_prod
  password: "xK9#mP2$vL5nQ8wR"
  pool: 25
  timeout: 5000

staging:
  adapter: mysql2
  host: 10.0.1.60
  database: staging_db
  username: webapp_staging
  password: "staging_pass_2025"
  pool: 10

development:
  adapter: sqlite3
  database: db/development.sqlite3
EOF

cat > /opt/webapp/config/secrets.yml << 'EOF'
production:
  secret_key_base: 3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4
  admin_password: "Adm1n_Pr0d_2025!!"
  encryption_key: "aes-256-cbc-key-do-not-share-12345"
  oauth:
    github_client_id: "Iv1.abc123def456"
    github_client_secret: "ghsecret_abcdefghijklmnopqrstuvwxyz"
    google_client_id: "123456789-abc.apps.googleusercontent.com"
    google_client_secret: "GOCSPX-abcdefghijklmnop"
EOF

cat > /opt/webapp/docker-compose.yml << 'EOF'
version: '3.8'
services:
  api:
    image: company/webapp-api:latest
    env_file: .env
    ports:
      - "3000:3000"
    depends_on:
      - redis
    restart: always

  worker:
    image: company/webapp-worker:latest
    env_file: .env
    depends_on:
      - redis
    restart: always

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - /etc/letsencrypt:/etc/letsencrypt:ro
    restart: always

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass R3dis_Pr0d_Pass!
    volumes:
      - redis_data:/data
    restart: always

volumes:
  redis_data:
EOF

# ---------------------------------------------------------------------------
# Crypto wallet / trading bot files
# ---------------------------------------------------------------------------
echo "[+] Planting crypto honeytokens..."

mkdir -p /home/mkovacs/crypto-bot /home/mkovacs/.bitcoin

cat > /home/mkovacs/crypto-bot/config.json << 'EOF'
{
    "exchange": "binance",
    "api_key": "vM3xR7kLp9Qw2nJ5tY8uB4cF6hA0dE1",
    "api_secret": "zX9wV7uT5sR3qP1oN8mL6kJ4hG2fD0c",
    "trading_pairs": ["BTC/USDT", "ETH/USDT", "SOL/USDT"],
    "strategy": "grid_trading",
    "investment_usd": 50000,
    "max_position_pct": 0.15,
    "stop_loss_pct": 0.05,
    "wallet_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    "eth_wallet": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68",
    "private_key": "0x4c0883a69102937d6231471b5dbb6204fe512961708279f23efb56e3b2e4d30d"
}
EOF

cat > /home/mkovacs/.bitcoin/bitcoin.conf << 'EOF'
rpcuser=bitcoinrpc
rpcpassword=5xyZ9k3mP7qW2nR8vL4jT6hB0cF1aD
rpcallowip=127.0.0.1
server=1
testnet=0
wallet=main_wallet
EOF

cat > /home/mkovacs/crypto-bot/.env << 'EOF'
INFURA_API_KEY=a1b2c3d4e5f6g7h8i9j0
ETHERSCAN_API_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZ123456
COINMARKETCAP_API=cmc_1234567890abcdef
TELEGRAM_BOT_TOKEN=6123456789:AAFakeTokenHereForAlerts
TELEGRAM_CHAT_ID=-1001234567890
EOF

# Fake wallet seed (BIP39 — this is NOT a real wallet)
cat > /home/mkovacs/.bitcoin/seed_backup.txt << 'EOF'
### WALLET SEED PHRASE — KEEP SAFE ###
abandon ability able about above absent absorb abstract absurd abuse access accident
### Generated: 2025-11-15 ###
### Wallet: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh ###
EOF
chmod 600 /home/mkovacs/.bitcoin/seed_backup.txt

chown -R mkovacs:mkovacs /home/mkovacs/

# ---------------------------------------------------------------------------
# Database configs & credentials
# ---------------------------------------------------------------------------
echo "[+] Planting database configs..."

mkdir -p /etc/mysql /var/lib/mysql /opt/backups

cat > /root/.my.cnf << 'EOF'
[client]
user=root
password=r00t_MySQL_2025!!
host=localhost
EOF
chmod 600 /root/.my.cnf

cat > /home/dbadmin/.pgpass << 'EOF'
10.0.1.50:5432:production:dbadmin:P0stgr3s_Pr0d_2025!
10.0.1.60:5432:staging:dbadmin:staging_pg_pass
localhost:5432:*:postgres:local_pg_admin
EOF
chmod 600 /home/dbadmin/.pgpass
chown dbadmin:dbadmin /home/dbadmin/.pgpass

# ---------------------------------------------------------------------------
# Fake backup scripts
# ---------------------------------------------------------------------------
echo "[+] Creating backup scripts..."

mkdir -p /root/scripts

cat > /root/scripts/backup.sh << 'BKEOF'
#!/bin/bash
# Daily database backup — runs at 2am via cron
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/backups"

# MySQL
mysqldump -u root -p'r00t_MySQL_2025!!' -h 10.0.1.50 --all-databases > "$BACKUP_DIR/mysql_full_$TIMESTAMP.sql"

# PostgreSQL
PGPASSWORD="P0stgr3s_Pr0d_2025!" pg_dump -h 10.0.1.50 -U dbadmin production > "$BACKUP_DIR/pg_prod_$TIMESTAMP.sql"

# Compress and upload to S3
tar czf "$BACKUP_DIR/backup_$TIMESTAMP.tar.gz" "$BACKUP_DIR"/*.sql
aws s3 cp "$BACKUP_DIR/backup_$TIMESTAMP.tar.gz" s3://company-prod-backups/daily/

# Cleanup old backups
find "$BACKUP_DIR" -name "*.sql" -mtime +7 -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete

echo "Backup complete: $TIMESTAMP"
BKEOF
chmod 755 /root/scripts/backup.sh

cat > /root/scripts/deploy.sh << 'EOF'
#!/bin/bash
# Production deployment script
cd /opt/webapp
git pull origin main
docker-compose build --no-cache
docker-compose down
docker-compose up -d
sleep 5
curl -sf http://localhost:3000/health || echo "DEPLOY FAILED"
curl -X POST -H "Content-Type: application/json" \
    -d '{"text":"Production deployed by '"$(whoami)"' at '"$(date)"'"}' \
    "https://FAKE-HONEYPOT-SLACK-WEBHOOK-NOT-REAL"
EOF
chmod 755 /root/scripts/deploy.sh

# ---------------------------------------------------------------------------
# Fake crontabs
# ---------------------------------------------------------------------------
echo "[+] Setting up crontabs..."

# Root crontab
cat > /var/spool/cron/crontabs/root << 'EOF'
# Database backup — daily 2am
0 2 * * * /root/scripts/backup.sh >> /var/log/backup.log 2>&1

# SSL cert renewal — weekly
0 4 * * 0 certbot renew --quiet --post-hook "systemctl reload nginx"

# Cleanup temp files
0 6 * * * find /tmp -type f -mtime +3 -delete

# System updates — monthly
0 3 1 * * apt update && apt upgrade -y >> /var/log/auto-update.log 2>&1

# Monitoring heartbeat
*/5 * * * * curl -sf https://heartbeat.company-internal.com/ping/abc-123-def || true
EOF
chmod 600 /var/spool/cron/crontabs/root
chown root:crontab /var/spool/cron/crontabs/root

# ---------------------------------------------------------------------------
# Fake services / systemd units
# ---------------------------------------------------------------------------
echo "[+] Creating fake services..."

cat > /etc/systemd/system/webapp-api.service << 'EOF'
[Unit]
Description=Production Web Application API
After=network.target mysql.service redis-server.service
Wants=mysql.service

[Service]
Type=simple
User=appuser
WorkingDirectory=/opt/webapp
EnvironmentFile=/opt/webapp/.env
ExecStart=/usr/bin/node /opt/webapp/server.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/backup-agent.service << 'EOF'
[Unit]
Description=Backup Agent — S3 sync
After=network.target

[Service]
Type=oneshot
ExecStart=/root/scripts/backup.sh
User=root
Environment=AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
Environment=AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/monitoring-agent.service << 'EOF'
[Unit]
Description=Prometheus Node Exporter + Custom Metrics
After=network.target

[Service]
Type=simple
User=prometheus
ExecStart=/usr/local/bin/node_exporter --web.listen-address=:9100
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# ---------------------------------------------------------------------------
# Nginx config (fake but realistic)
# ---------------------------------------------------------------------------
echo "[+] Setting up nginx config..."

mkdir -p /etc/nginx/sites-enabled /etc/nginx/ssl /var/www/html

cat > /etc/nginx/sites-enabled/webapp.conf << 'EOF'
upstream api_backend {
    server 127.0.0.1:3000;
    server 10.0.1.51:3000 backup;
}

server {
    listen 80;
    server_name api.company-internal.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name api.company-internal.com;

    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;

    location / {
        proxy_pass http://api_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /admin {
        proxy_pass http://api_backend;
        allow 10.0.0.0/8;
        allow 192.168.0.0/16;
        deny all;
    }
}
EOF

# Generate self-signed cert
openssl req -new -x509 -nodes -days 365 \
    -subj "/C=US/ST=CA/L=SF/O=Company Inc/CN=api.company-internal.com" \
    -keyout /etc/nginx/ssl/server.key \
    -out /etc/nginx/ssl/server.crt 2>/dev/null

# ---------------------------------------------------------------------------
# Fake /etc/hosts (internal network)
# ---------------------------------------------------------------------------
echo "[+] Populating /etc/hosts..."

cat >> /etc/hosts << 'EOF'

# Internal services
10.0.1.50    prod-db-01.internal db-master
10.0.1.51    prod-web-02.internal web-02
10.0.1.52    redis-01.internal cache
10.0.1.53    mongo-01.internal nosql
10.0.1.55    backup-srv.internal backups
10.0.1.60    staging-db-01.internal staging-db
10.0.1.61    staging-web-01.internal staging-web
10.0.1.100   bastion.company-internal.com bastion
10.0.1.200   jenkins.internal ci
10.0.1.201   gitlab.internal git
10.0.1.202   grafana.internal monitoring
10.0.1.203   vault.internal secrets
EOF

# ---------------------------------------------------------------------------
# Fake Kubernetes / cloud configs
# ---------------------------------------------------------------------------
echo "[+] Planting cloud configs..."

mkdir -p /home/devops/.kube /home/devops/.aws

cat > /home/devops/.kube/config << 'EOF'
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://k8s-api.company-internal.com:6443
    certificate-authority-data: LS0tLS1CRUdJTi...FAKEBASE64...
  name: production
- cluster:
    server: https://k8s-staging.company-internal.com:6443
  name: staging
contexts:
- context:
    cluster: production
    user: admin
    namespace: production
  name: prod-ctx
current-context: prod-ctx
users:
- name: admin
  user:
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IkZBS0UifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6YWRtaW4ifQ.FAKESIGNATURE
EOF

cat > /home/devops/.aws/credentials << 'EOF'
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[production]
aws_access_key_id = AKIA2OGYBAH6EXAMPLE
aws_secret_access_key = 7pQr5tUv8wXy1zA3bC6dE9fG2hI5jK8lMnOpQr
region = us-east-1

[backup]
aws_access_key_id = AKIA3XYZABC1EXAMPLE
aws_secret_access_key = mN0pQ1rS2tU3vW4xY5zA6bC7dE8fG9hI0jK1lM
EOF

cat > /home/devops/.aws/config << 'EOF'
[default]
region = us-east-1
output = json

[profile production]
region = us-east-1
role_arn = arn:aws:iam::123456789012:role/ProductionAdmin
source_profile = default
EOF

chown -R devops:devops /home/devops/

# ---------------------------------------------------------------------------
# Ansible vault / inventory
# ---------------------------------------------------------------------------
echo "[+] Creating ansible configs..."

mkdir -p /opt/ansible/inventory /opt/ansible/group_vars

cat > /opt/ansible/inventory/production << 'EOF'
[webservers]
prod-web-01 ansible_host=10.0.1.51 ansible_user=deploy
prod-web-02 ansible_host=10.0.1.52 ansible_user=deploy

[databases]
prod-db-01 ansible_host=10.0.1.50 ansible_user=dbadmin
prod-db-02 ansible_host=10.0.1.55 ansible_user=dbadmin

[monitoring]
grafana ansible_host=10.0.1.202 ansible_user=admin
prometheus ansible_host=10.0.1.203 ansible_user=prometheus

[all:vars]
ansible_ssh_private_key_file=/home/ansible/.ssh/id_rsa
ansible_become=yes
ansible_become_password=Ans1ble_Suд0_2025!
EOF

cat > /opt/ansible/group_vars/all.yml << 'EOF'
---
# Ansible vault password: V4ult_M4ster_Key_2025!
db_root_password: "r00t_MySQL_2025!!"
redis_password: "R3dis_Pr0d_Pass!"
api_secret_key: "super_secret_jwt_key_do_not_share_2025"
smtp_password: "SG.aBcDeFgHiJkLmNoPqRsT"
slack_webhook: "https://FAKE-HONEYPOT-SLACK-WEBHOOK-NOT-REAL"
backup_s3_bucket: "company-prod-backups"
ssl_cert_path: "/etc/nginx/ssl/server.crt"
ssl_key_path: "/etc/nginx/ssl/server.key"
EOF

# ---------------------------------------------------------------------------
# Fake log files to make it look active
# ---------------------------------------------------------------------------
echo "[+] Generating fake log entries..."

mkdir -p /opt/webapp/logs /var/log/nginx

# Fake nginx access log
for i in $(seq 1 50); do
    IP="$(shuf -i 1-223 -n 1).$(shuf -i 0-255 -n 1).$(shuf -i 0-255 -n 1).$(shuf -i 0-255 -n 1)"
    CODE=$(shuf -e 200 200 200 200 301 404 500 -n 1)
    echo "$IP - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /api/v1/users HTTP/1.1\" $CODE $(shuf -i 100-5000 -n 1) \"-\" \"Mozilla/5.0\"" >> /var/log/nginx/access.log
done

# Fake app log
for i in $(seq 1 30); do
    echo "[$(date -u +%Y-%m-%dT%H:%M:%S)Z] INFO  server: Request processed in $(shuf -i 10-500 -n 1)ms path=/api/v1/$(shuf -e users orders payments webhooks -n 1)" >> /opt/webapp/logs/app.log
done

# ---------------------------------------------------------------------------
# HashiCorp Vault token (fake)
# ---------------------------------------------------------------------------
echo "[+] Planting vault tokens..."

mkdir -p /root/.vault-tokens
cat > /root/.vault-token << 'EOF'
hvs.CAESIFakeVaultTokenHereForHoneypotPurposes12345678
EOF
chmod 600 /root/.vault-token

cat > /etc/profile.d/vault.sh << 'EOF'
export VAULT_ADDR="https://vault.internal:8200"
export VAULT_TOKEN="hvs.CAESIFakeVaultTokenHereForHoneypotPurposes12345678"
EOF

# ---------------------------------------------------------------------------
# Jenkins credentials
# ---------------------------------------------------------------------------
mkdir -p /var/lib/jenkins/secrets
cat > /var/lib/jenkins/secrets/master.key << 'EOF'
7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b
EOF
cat > /var/lib/jenkins/credentials.xml << 'EOF'
<?xml version='1.0' encoding='UTF-8'?>
<credentials>
  <entry>
    <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
      <id>prod-deploy</id>
      <username>deploy</username>
      <password>D3pl0y_Pr0d_2025!!</password>
    </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
  </entry>
  <entry>
    <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
      <id>github-bot</id>
      <username>company-bot</username>
      <password>ghp_FakeGitHubTokenForHoneypot1234567890</password>
    </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
  </entry>
</credentials>
EOF

# ---------------------------------------------------------------------------
# Git config to make it look like a dev server
# ---------------------------------------------------------------------------
echo "[+] Setting up git configs..."

mkdir -p /opt/webapp/.git
cat > /opt/webapp/.git/config << 'EOF'
[core]
    repositoryformatversion = 0
    filemode = true
[remote "origin"]
    url = git@gitlab.internal:company/webapp.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
[user]
    name = Deploy Bot
    email = deploy@company-internal.com
EOF

# ---------------------------------------------------------------------------
# MOTD — make it look like a managed server
# ---------------------------------------------------------------------------
echo "[+] Setting MOTD..."

cat > /etc/motd << 'EOF'

  ╔══════════════════════════════════════════════════════════╗
  ║        COMPANY INC — PRODUCTION SERVER                  ║
  ║                                                          ║
  ║  Hostname: prod-app-01    Environment: PRODUCTION       ║
  ║  Owner: Platform Team     Contact: ops@company.com      ║
  ║                                                          ║
  ║  ⚠ AUTHORIZED ACCESS ONLY — All activity is logged      ║
  ║  Unauthorized access will be prosecuted under 18 USC §1030║
  ╚══════════════════════════════════════════════════════════╝

EOF

# ---------------------------------------------------------------------------
# Fake processes via simple scripts
# ---------------------------------------------------------------------------
echo "[+] Creating fake processes..."

cat > /opt/webapp/server.js << 'EOF'
// Fake — just holds the port open
const http = require('http');
const server = http.createServer((req, res) => {
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({status: 'ok', version: '2.4.1', env: 'production'}));
});
server.listen(3000, () => console.log('API server running on :3000'));
EOF

# ---------------------------------------------------------------------------
# Fix permissions
# ---------------------------------------------------------------------------
echo "[+] Fixing ownership..."

for user in jchen srao mkovacs deploy webadmin dbadmin devops ansible; do
    chown -R "$user:$user" "/home/$user" 2>/dev/null || true
done

echo ""
echo "=== Honeypot Decoys Deployed ==="
echo "Users: ${#USERS[@]} accounts created"
echo "Configs: webapp .env, database.yml, secrets.yml"
echo "Crypto: wallet configs, trading bot, seed phrase"
echo "Cloud: AWS creds, K8s config, Vault tokens"
echo "CI/CD: Jenkins credentials, Ansible vault"
echo "History: bash histories with leaked commands"
echo "Services: webapp-api, backup-agent, monitoring-agent"
