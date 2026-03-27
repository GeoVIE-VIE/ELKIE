#!/usr/bin/env python3
"""
Cover Story Generator for ELKIE Sacrificial VM Honeypot

Generates a complete set of decoy files from a YAML config or env vars:
  - SSL cert, /etc/hosts, MOTD, users, credentials, bash histories,
    nginx config, systemd units, and more.

Output is a directory tree ready to SCP to the sacrificial VM.

Usage:
    python3 generate_cover.py --config cover_stories/default.yml --output /tmp/cover_output
    python3 generate_cover.py --from-env --output /tmp/cover_output
"""

import argparse
import os
import stat
import sys
import textwrap
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Install with: pip3 install pyyaml", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Defaults — used when YAML fields are missing
# ---------------------------------------------------------------------------
DEFAULTS = {
    "company": {
        "name": "Dirigo Systems LLC",
        "domain": "dirigosystems.net",
        "hostname": "ds-prod-web01",
        "city": "Auburn",
        "state": "Maine",
        "country": "US",
        "industry": "software",
        "internal_domain": "company-internal.com",
        "tagline": "Secure Cloud Infrastructure",
        "contact_email": "ops@dirigosystems.net",
        "team_name": "Platform Team",
    },
    "ssl": {
        "cn": "portal.dirigosystems.net",
        "org": "Dirigo Systems LLC",
        "days": 365,
    },
}


def load_config(path):
    """Load YAML config file."""
    with open(path) as f:
        cfg = yaml.safe_load(f)
    # Merge defaults for missing top-level keys
    for section, defaults in DEFAULTS.items():
        if section not in cfg:
            cfg[section] = {}
        for k, v in defaults.items():
            cfg[section].setdefault(k, v)
    return cfg


def config_from_env():
    """Build config dict from COVER_* environment variables."""
    company_name = os.environ.get("COVER_COMPANY", DEFAULTS["company"]["name"])
    domain = os.environ.get("COVER_DOMAIN", DEFAULTS["company"]["domain"])
    hostname = os.environ.get("COVER_HOSTNAME", DEFAULTS["company"]["hostname"])
    city = os.environ.get("COVER_CITY", DEFAULTS["company"]["city"])
    state_name = os.environ.get("COVER_STATE", DEFAULTS["company"]["state"])
    country = os.environ.get("COVER_COUNTRY", DEFAULTS["company"]["country"])

    return {
        "company": {
            "name": company_name,
            "domain": domain,
            "hostname": hostname,
            "city": city,
            "state": state_name,
            "country": country,
            "industry": "software",
            "internal_domain": "company-internal.com",
            "tagline": "Secure Cloud Infrastructure",
            "contact_email": f"ops@{domain}",
            "team_name": "Platform Team",
        },
        "ssl": {
            "cn": os.environ.get("COVER_SSL_CN", f"portal.{domain}"),
            "org": os.environ.get("COVER_SSL_ORG", company_name),
            "days": 365,
        },
        "users": _default_users(),
        "services": _default_services(),
        "network": _default_network(),
        "credentials": _default_credentials(),
    }


# ---------------------------------------------------------------------------
# Default data generators (used when --from-env or YAML omits sections)
# ---------------------------------------------------------------------------

def _default_users():
    return [
        {"name": "jchen", "full_name": "Jason Chen", "role": "devops"},
        {"name": "srao", "full_name": "Sunita Rao", "role": "sre"},
        {"name": "mkovacs", "full_name": "Milan Kovacs", "role": "developer", "crypto_user": True},
        {"name": "deploy", "full_name": "Deploy Bot", "role": "service"},
        {"name": "jenkins", "full_name": "Jenkins CI", "role": "service"},
        {"name": "gitlab-runner", "full_name": "GitLab Runner", "role": "service"},
        {"name": "nagios", "full_name": "Nagios Monitoring", "role": "service"},
        {"name": "backup", "full_name": "Backup Service", "role": "service"},
        {"name": "webadmin", "full_name": "Web Administrator", "role": "admin"},
        {"name": "dbadmin", "full_name": "Database Admin", "role": "admin"},
        {"name": "appuser", "full_name": "Application Service", "role": "service"},
        {"name": "devops", "full_name": "DevOps Team", "role": "devops"},
        {"name": "ftpuser", "full_name": "FTP Upload", "role": "service"},
        {"name": "redis", "full_name": "Redis Service", "role": "service"},
        {"name": "mongodb", "full_name": "MongoDB Service", "role": "service"},
        {"name": "elastic", "full_name": "Elasticsearch", "role": "service"},
        {"name": "docker", "full_name": "Docker Service", "role": "service"},
        {"name": "ansible", "full_name": "Ansible Automation", "role": "devops"},
        {"name": "prometheus", "full_name": "Prometheus Monitoring", "role": "service"},
        {"name": "www-data", "full_name": "Web Server", "role": "service"},
    ]


def _default_services():
    return [
        {
            "name": "webapp-api",
            "description": "Production Web Application API",
            "port": 3000,
            "user": "appuser",
            "type": "node",
            "exec": "/usr/bin/node /opt/webapp/server.js",
            "after": "network.target mysql.service redis-server.service",
        },
        {
            "name": "backup-agent",
            "description": "Backup Agent — S3 sync",
            "type": "oneshot",
            "user": "root",
            "exec": "/root/scripts/backup.sh",
        },
        {
            "name": "monitoring-agent",
            "description": "Prometheus Node Exporter + Custom Metrics",
            "port": 9100,
            "user": "prometheus",
            "type": "simple",
            "exec": "/usr/local/bin/node_exporter --web.listen-address=:9100",
        },
    ]


def _default_network():
    return {
        "internal_hosts": [
            {"ip": "10.0.1.50", "names": ["prod-db-01.internal", "db-master"]},
            {"ip": "10.0.1.51", "names": ["prod-web-02.internal", "web-02"]},
            {"ip": "10.0.1.52", "names": ["redis-01.internal", "cache"]},
            {"ip": "10.0.1.53", "names": ["mongo-01.internal", "nosql"]},
            {"ip": "10.0.1.55", "names": ["backup-srv.internal", "backups"]},
            {"ip": "10.0.1.60", "names": ["staging-db-01.internal", "staging-db"]},
            {"ip": "10.0.1.61", "names": ["staging-web-01.internal", "staging-web"]},
            {"ip": "10.0.1.100", "names": ["bastion.company-internal.com", "bastion"]},
            {"ip": "10.0.1.200", "names": ["jenkins.internal", "ci"]},
            {"ip": "10.0.1.201", "names": ["gitlab.internal", "git"]},
            {"ip": "10.0.1.202", "names": ["grafana.internal", "monitoring"]},
            {"ip": "10.0.1.203", "names": ["vault.internal", "secrets"]},
        ]
    }


def _default_credentials():
    return {
        "aws": {
            "profiles": [
                {"name": "default", "access_key": "AKIAIOSFODNN7EXAMPLE",
                 "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
                {"name": "production", "access_key": "AKIA2OGYBAH6EXAMPLE",
                 "secret_key": "7pQr5tUv8wXy1zA3bC6dE9fG2hI5jK8lMnOpQr", "region": "us-east-1"},
                {"name": "backup", "access_key": "AKIA3XYZABC1EXAMPLE",
                 "secret_key": "mN0pQ1rS2tU3vW4xY5zA6bC7dE8fG9hI0jK1lM"},
            ]
        },
        "databases": {
            "mysql_root": "r00t_MySQL_2025!!",
            "postgres_prod": "P0stgr3s_Pr0d_2025!",
            "redis": "R3dis_Pr0d_Pass!",
            "mongo": "M0ng0_Adm1n_2025",
            "webapp_db": "xK9#mP2$vL5nQ8wR",
        },
        "crypto": {
            "binance_key": "vM3xR7kLp9Qw2nJ5tY8uB4cF6hA0dE1",
            "binance_secret": "zX9wV7uT5sR3qP1oN8mL6kJ4hG2fD0c",
            "btc_wallet": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            "eth_wallet": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68",
            "eth_private_key": "0x4c0883a69102937d6231471b5dbb6204fe512961708279f23efb56e3b2e4d30d",
            "btc_rpc_pass": "5xyZ9k3mP7qW2nR8vL4jT6hB0cF1aD",
            "seed_phrase": "abandon ability able about above absent absorb abstract absurd abuse access accident",
        },
        "jenkins": {
            "deploy_pass": "D3pl0y_Pr0d_2025!!",
            "github_token": "ghp_FakeGitHubTokenForHoneypot1234567890",
            "master_key": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
        },
        "vault": {
            "token": "hvs.CAESIFakeVaultTokenHereForHoneypotPurposes12345678",
            "addr": "https://vault.internal:8200",
        },
        "app": {
            "jwt_secret": "super_secret_jwt_key_do_not_share_2025",
            "api_key": "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789",
            "stripe_key": "FAKE_HONEYPOT_STRIPE_KEY_NOT_REAL",
            "stripe_webhook": "whsec_1234567890abcdefghijklmnop",
            "sendgrid_key": "SG.aBcDeFgHiJkLmNoPqRsT.UvWxYz1234567890abcdefghij",
            "sentry_dsn": "https://abc123@o456.ingest.sentry.io/789",
            "grafana_pass": "Gr4fana_Adm1n!",
            "ansible_sudo": "Ans1ble_Sud0_2025!",
            "vault_master": "V4ult_M4ster_Key_2025!",
        },
    }


# ---------------------------------------------------------------------------
# Helper to write files with permissions
# ---------------------------------------------------------------------------

def write_file(base, rel_path, content, mode=0o644, executable=False):
    """Write a file under base/rel_path, creating parent dirs as needed."""
    full = Path(base) / rel_path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content)
    if executable:
        full.chmod(0o755)
    else:
        full.chmod(mode)


# ---------------------------------------------------------------------------
# Asset generators
# ---------------------------------------------------------------------------

def gen_ssl_script(cfg, base):
    """Generate an SSL cert generation script (runs on target)."""
    ssl = cfg["ssl"]
    co = cfg["company"]
    script = textwrap.dedent(f"""\
        #!/bin/bash
        # Generate self-signed SSL cert for honeypot cover story
        mkdir -p /etc/nginx/ssl
        openssl req -new -x509 -nodes -days {ssl['days']} \\
            -subj "/C={co['country']}/ST={co['state']}/L={co['city']}/O={ssl['org']}/CN={ssl['cn']}" \\
            -keyout /etc/nginx/ssl/server.key \\
            -out /etc/nginx/ssl/server.crt 2>/dev/null
        chmod 600 /etc/nginx/ssl/server.key
        echo "[+] SSL cert generated: CN={ssl['cn']}, O={ssl['org']}"
    """)
    write_file(base, "scripts/gen_ssl.sh", script, executable=True)


def gen_etc_hosts(cfg, base):
    """Generate /etc/hosts additions."""
    network = cfg.get("network", _default_network())
    lines = ["\n# Internal services — generated by cover story generator"]
    for entry in network.get("internal_hosts", []):
        names = "    ".join(entry["names"])
        lines.append(f"{entry['ip']}    {names}")
    write_file(base, "etc/hosts.append", "\n".join(lines) + "\n")


def gen_motd(cfg, base):
    """Generate /etc/motd."""
    co = cfg["company"]
    hostname = co.get("hostname", "prod-01")
    team = co.get("team_name", "Platform Team")
    email = co.get("contact_email", f"ops@{co['domain']}")
    company_upper = co["name"].upper()

    # Build dynamic-width box
    title_line = f"{company_upper} -- PRODUCTION SERVER"
    info1 = f"Hostname: {hostname}    Environment: PRODUCTION"
    info2 = f"Owner: {team}     Contact: {email}"
    warn = "WARNING: AUTHORIZED ACCESS ONLY -- All activity is logged"
    legal = "Unauthorized access will be prosecuted under 18 USC 1030"

    all_lines = [title_line, "", info1, info2, "", warn, legal]
    width = max(len(l) for l in all_lines) + 4

    motd_lines = [""]
    motd_lines.append("  " + "=" * (width + 4))
    for line in all_lines:
        motd_lines.append(f"  |  {line:<{width}}|")
    motd_lines.append("  " + "=" * (width + 4))
    motd_lines.append("")

    write_file(base, "etc/motd", "\n".join(motd_lines) + "\n")


def gen_users_script(cfg, base):
    """Generate user creation script."""
    users = cfg.get("users", _default_users())
    lines = ["#!/bin/bash", "# Create honeypot user accounts", "set -e", ""]
    lines.append('echo "[+] Creating user accounts..."')

    for u in users:
        name = u["name"]
        full = u["full_name"]
        lines.append(f'id "{name}" &>/dev/null || useradd -m -s /bin/bash -c "{full}" "{name}" 2>/dev/null || true')

    lines.append("")
    lines.append(f'echo "[+] Created {len(users)} user accounts"')
    write_file(base, "scripts/create_users.sh", "\n".join(lines) + "\n", executable=True)


def gen_ssh_keys(cfg, base):
    """Generate SSH key generation script and configs for human users."""
    users = cfg.get("users", _default_users())
    co = cfg["company"]
    internal = co.get("internal_domain", "company-internal.com")

    ssh_users = [u for u in users if u.get("role") in ("devops", "sre", "developer", "admin")]

    lines = ["#!/bin/bash", "# Generate SSH keys and configs for honeypot users", "set -e", ""]

    for u in ssh_users:
        name = u["name"]
        lines.append(f'echo "[+] SSH setup for {name}"')
        lines.append(f'HOME_DIR="/home/{name}"')
        lines.append(f'mkdir -p "$HOME_DIR/.ssh"')
        lines.append(f'ssh-keygen -t ed25519 -f "$HOME_DIR/.ssh/id_ed25519" -N "" -q 2>/dev/null || true')
        lines.append(f'ssh-keygen -t rsa -b 2048 -f "$HOME_DIR/.ssh/id_rsa" -N "" -q 2>/dev/null || true')
        lines.append("")

    # Write SSH config template
    lines.append("# Write SSH configs for human users")
    for u in ssh_users:
        name = u["name"]
        lines.append(f'cat > /home/{name}/.ssh/config << \'SSHEOF\'')
        lines.append("Host prod-db-*")
        lines.append("    User dbadmin")
        lines.append("    IdentityFile ~/.ssh/id_rsa")
        lines.append("    Port 22")
        lines.append("")
        lines.append("Host staging-*")
        lines.append("    User deploy")
        lines.append("    IdentityFile ~/.ssh/id_ed25519")
        lines.append("    StrictHostKeyChecking no")
        lines.append("")
        lines.append("Host *.internal")
        lines.append(f"    ProxyJump bastion.{internal}")
        lines.append("    User svc-deploy")
        lines.append("")
        lines.append("Host bastion")
        lines.append(f"    HostName 203.0.113.50")
        lines.append(f"    User {name}")
        lines.append("    Port 2222")
        lines.append("SSHEOF")
        lines.append("")

    # Write known_hosts
    lines.append("# Fake known_hosts for all SSH users")
    for u in ssh_users:
        name = u["name"]
        lines.append(f'cat > /home/{name}/.ssh/known_hosts << \'KHEOF\'')
        lines.append("10.0.1.50 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKqR3kMwJx7YvO2PqFHzVJxL4m5NrJ0X6vWL+yGh1234")
        lines.append("10.0.1.51 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbM9pLdX5zZ3wK8fhYvP0qTt2nM6xR0L+yGh5678")
        lines.append(f"prod-db-01.internal ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxyz...")
        lines.append(f"staging-web-03.internal ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyHere")
        lines.append(f"git.{internal} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMoreFakeKeys")
        lines.append("KHEOF")
        lines.append("")

    # Fix permissions
    lines.append("# Fix permissions")
    for u in ssh_users:
        name = u["name"]
        lines.append(f'chown -R "{name}:{name}" "/home/{name}/.ssh" 2>/dev/null || true')
        lines.append(f'chmod 700 "/home/{name}/.ssh"')
        lines.append(f'chmod 600 "/home/{name}/.ssh/"* 2>/dev/null || true')

    write_file(base, "scripts/setup_ssh.sh", "\n".join(lines) + "\n", executable=True)


def gen_bash_histories(cfg, base):
    """Generate fake .bash_history for key users."""
    co = cfg["company"]
    creds = cfg.get("credentials", _default_credentials())
    db = creds.get("databases", {})
    crypto = creds.get("crypto", {})
    app = creds.get("app", {})
    domain = co.get("internal_domain", "company-internal.com")

    # Find users by role for bash history
    users = cfg.get("users", _default_users())
    devops_users = [u for u in users if u.get("role") in ("devops", "sre")]
    crypto_users = [u for u in users if u.get("crypto_user")]
    admin_users = [u for u in users if u.get("role") == "admin"]

    # DevOps history template
    devops_history = textwrap.dedent(f"""\
        cd /opt/webapp
        git pull origin main
        docker-compose up -d
        docker logs -f webapp_api_1
        tail -f /var/log/nginx/access.log
        mysql -u root -p'{db.get("mysql_root", "password")}' -h 10.0.1.50 production_db
        mysqldump -u root -p'{db.get("mysql_root", "password")}' -h 10.0.1.50 production_db > /tmp/prod_backup.sql
        scp /tmp/prod_backup.sql backup@10.0.1.55:/mnt/backups/
        kubectl get pods -n production
        kubectl logs -f deploy/api-server -n production
        ssh deploy@staging-web-03.internal
        curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.fake_jwt_token" https://api.internal/v1/users
        aws s3 ls s3://company-prod-backups/
        aws s3 cp s3://company-prod-backups/db-latest.tar.gz /tmp/
        export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        terraform plan -var-file=prod.tfvars
        ansible-playbook -i inventory/production deploy-webapp.yml
        cat /etc/shadow
        sudo cat /etc/shadow
        vim /opt/webapp/.env
        cat /opt/webapp/config/database.yml
        redis-cli -h 10.0.1.52 -a '{db.get("redis", "password")}'
        mongo --host 10.0.1.53 -u admin -p '{db.get("mongo", "password")}' --authenticationDatabase admin
    """)

    # SRE history template
    sre_history = textwrap.dedent(f"""\
        docker ps
        docker exec -it postgres_db psql -U admin
        pg_dump -U admin -h localhost production > /tmp/pg_backup.sql
        cd /opt/monitoring
        vim prometheus.yml
        systemctl restart prometheus
        grafana-cli admin reset-admin-password {app.get("grafana_pass", "password")}
        curl -u admin:{app.get("grafana_pass", "password")} http://localhost:3000/api/datasources
        kubectl get secrets -n production
        kubectl get secret db-credentials -n production -o jsonpath='{{.data.password}}' | base64 -d
        ssh -L 5432:prod-db-01.internal:5432 bastion
        psql -h localhost -p 5432 -U postgres -d production
        cat /opt/webapp/config/secrets.yml
        openssl req -new -x509 -key /etc/ssl/private/server.key -out /etc/ssl/certs/server.crt
        certbot renew --dry-run
    """)

    # Crypto user history
    crypto_history = textwrap.dedent(f"""\
        cd ~/crypto-bot
        python3 trading_bot.py --config config.json
        cat config.json
        vim config.json
        python3 -c "from web3 import Web3; w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/a1b2c3d4e5f6'))"
        node scripts/check_balance.js
        cat .env
        export BINANCE_API_KEY={crypto.get("binance_key", "key")}
        export BINANCE_SECRET={crypto.get("binance_secret", "secret")}
        bitcoin-cli getbalance
        bitcoin-cli listunspent
        cat ~/.bitcoin/bitcoin.conf
        python3 withdraw.py --amount 2.5 --address {crypto.get("btc_wallet", "bc1q...")}
        ssh {crypto_users[0]["name"] if crypto_users else "user"}@exchange-api.internal
        curl -H "X-MBX-APIKEY: {crypto.get("binance_key", "key")}" "https://api.binance.com/api/v3/account"
    """)

    # Root history
    root_history = textwrap.dedent(f"""\
        apt update && apt upgrade -y
        systemctl status nginx mysql redis-server
        tail -f /var/log/syslog
        iptables -L -n
        netstat -tulpn
        cat /etc/shadow
        passwd deploy
        usermod -aG sudo {devops_users[0]["name"] if devops_users else "admin"}
        vim /etc/nginx/sites-enabled/webapp.conf
        certbot certonly --nginx -d api.{domain}
        mysql -u root -p
        mysql -u root -p'{db.get("mysql_root", "password")}'
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
    """)

    # Write histories
    if devops_users:
        write_file(base, f"home/{devops_users[0]['name']}/.bash_history", devops_history)
    if len(devops_users) > 1 or [u for u in users if u.get("role") == "sre"]:
        sre_user = next((u for u in users if u.get("role") == "sre"), devops_users[-1] if devops_users else None)
        if sre_user:
            write_file(base, f"home/{sre_user['name']}/.bash_history", sre_history)
    if crypto_users:
        write_file(base, f"home/{crypto_users[0]['name']}/.bash_history", crypto_history)

    write_file(base, "root/.bash_history", root_history)


def gen_aws_creds(cfg, base):
    """Generate ~/.aws/credentials and config for devops user."""
    creds = cfg.get("credentials", _default_credentials())
    aws = creds.get("aws", {})
    profiles = aws.get("profiles", [])

    users = cfg.get("users", _default_users())
    devops_user = next((u for u in users if u.get("role") == "devops"), None)
    if not devops_user:
        return
    name = devops_user["name"]

    # credentials file
    cred_lines = []
    config_lines = []
    for p in profiles:
        section = p["name"]
        cred_lines.append(f"[{section}]")
        cred_lines.append(f"aws_access_key_id = {p['access_key']}")
        cred_lines.append(f"aws_secret_access_key = {p['secret_key']}")
        cred_lines.append("")

        config_lines.append(f"[{'profile ' + section if section != 'default' else 'default'}]")
        config_lines.append(f"region = {p.get('region', 'us-east-1')}")
        config_lines.append("output = json")
        if section != "default":
            config_lines.append(f"role_arn = arn:aws:iam::123456789012:role/{section.title()}Admin")
            config_lines.append("source_profile = default")
        config_lines.append("")

    write_file(base, f"home/{name}/.aws/credentials", "\n".join(cred_lines), mode=0o600)
    write_file(base, f"home/{name}/.aws/config", "\n".join(config_lines), mode=0o600)


def gen_kube_config(cfg, base):
    """Generate ~/.kube/config for devops user."""
    co = cfg["company"]
    internal = co.get("internal_domain", "company-internal.com")

    users = cfg.get("users", _default_users())
    devops_user = next((u for u in users if u.get("role") == "devops"), None)
    if not devops_user:
        return
    name = devops_user["name"]

    kube = textwrap.dedent(f"""\
        apiVersion: v1
        kind: Config
        clusters:
        - cluster:
            server: https://k8s-api.{internal}:6443
            certificate-authority-data: LS0tLS1CRUdJTi...FAKEBASE64...
          name: production
        - cluster:
            server: https://k8s-staging.{internal}:6443
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
    """)
    write_file(base, f"home/{name}/.kube/config", kube, mode=0o600)


def gen_crypto_decoys(cfg, base):
    """Generate crypto wallet/trading bot decoys for crypto_user."""
    users = cfg.get("users", _default_users())
    crypto_user = next((u for u in users if u.get("crypto_user")), None)
    if not crypto_user:
        return
    name = crypto_user["name"]
    creds = cfg.get("credentials", _default_credentials())
    crypto = creds.get("crypto", {})

    # Trading bot config
    config_json = textwrap.dedent(f"""\
        {{
            "exchange": "binance",
            "api_key": "{crypto.get('binance_key', 'key')}",
            "api_secret": "{crypto.get('binance_secret', 'secret')}",
            "trading_pairs": ["BTC/USDT", "ETH/USDT", "SOL/USDT"],
            "strategy": "grid_trading",
            "investment_usd": 50000,
            "max_position_pct": 0.15,
            "stop_loss_pct": 0.05,
            "wallet_address": "{crypto.get('btc_wallet', 'bc1q...')}",
            "eth_wallet": "{crypto.get('eth_wallet', '0x...')}",
            "private_key": "{crypto.get('eth_private_key', '0x...')}"
        }}
    """)
    write_file(base, f"home/{name}/crypto-bot/config.json", config_json)

    # Bitcoin config
    btc_conf = textwrap.dedent(f"""\
        rpcuser=bitcoinrpc
        rpcpassword={crypto.get('btc_rpc_pass', 'password')}
        rpcallowip=127.0.0.1
        server=1
        testnet=0
        wallet=main_wallet
    """)
    write_file(base, f"home/{name}/.bitcoin/bitcoin.conf", btc_conf, mode=0o600)

    # Seed phrase
    seed = textwrap.dedent(f"""\
        ### WALLET SEED PHRASE -- KEEP SAFE ###
        {crypto.get('seed_phrase', 'abandon ...')}
        ### Generated: 2025-11-15 ###
        ### Wallet: {crypto.get('btc_wallet', 'bc1q...')} ###
    """)
    write_file(base, f"home/{name}/.bitcoin/seed_backup.txt", seed, mode=0o600)

    # Crypto .env
    crypto_env = textwrap.dedent("""\
        INFURA_API_KEY=a1b2c3d4e5f6g7h8i9j0
        ETHERSCAN_API_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZ123456
        COINMARKETCAP_API=cmc_1234567890abcdef
        TELEGRAM_BOT_TOKEN=6123456789:AAFakeTokenHereForAlerts
        TELEGRAM_CHAT_ID=-1001234567890
    """)
    write_file(base, f"home/{name}/crypto-bot/.env", crypto_env, mode=0o600)


def gen_webapp_configs(cfg, base):
    """Generate /opt/webapp configs, docker-compose, database.yml, secrets.yml."""
    co = cfg["company"]
    creds = cfg.get("credentials", _default_credentials())
    db = creds.get("databases", {})
    app_creds = creds.get("app", {})
    aws = creds.get("aws", {})
    aws_default = next((p for p in aws.get("profiles", []) if p["name"] == "default"), {})
    internal = co.get("internal_domain", "company-internal.com")

    # .env
    env_content = textwrap.dedent(f"""\
        # Production Environment -- DO NOT COMMIT
        NODE_ENV=production
        PORT=3000
        DB_HOST=10.0.1.50
        DB_PORT=3306
        DB_NAME=production_db
        DB_USER=webapp_prod
        DB_PASS={db.get('webapp_db', 'password')}
        REDIS_URL=redis://:{db.get('redis', 'password')}@10.0.1.52:6379
        MONGO_URI=mongodb://admin:{db.get('mongo', 'password')}@10.0.1.53:27017/app?authSource=admin
        JWT_SECRET={app_creds.get('jwt_secret', 'secret')}
        API_KEY={app_creds.get('api_key', 'key')}
        STRIPE_SECRET_KEY={app_creds.get('stripe_key', 'stripe')}
        STRIPE_WEBHOOK_SECRET={app_creds.get('stripe_webhook', 'whsec')}
        SENDGRID_API_KEY={app_creds.get('sendgrid_key', 'SG...')}
        AWS_ACCESS_KEY_ID={aws_default.get('access_key', 'AKIA...')}
        AWS_SECRET_ACCESS_KEY={aws_default.get('secret_key', 'secret')}
        AWS_REGION=us-east-1
        S3_BUCKET=company-prod-uploads
        SENTRY_DSN={app_creds.get('sentry_dsn', 'https://...')}
        SLACK_WEBHOOK=https://FAKE-HONEYPOT-SLACK-WEBHOOK-NOT-REAL
    """)
    write_file(base, "opt/webapp/.env", env_content, mode=0o600)

    # database.yml
    db_yml = textwrap.dedent(f"""\
        production:
          adapter: mysql2
          host: 10.0.1.50
          port: 3306
          database: production_db
          username: webapp_prod
          password: "{db.get('webapp_db', 'password')}"
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
    """)
    write_file(base, "opt/webapp/config/database.yml", db_yml)

    # secrets.yml
    secrets_yml = textwrap.dedent(f"""\
        production:
          secret_key_base: 3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4
          admin_password: "Adm1n_Pr0d_2025!!"
          encryption_key: "aes-256-cbc-key-do-not-share-12345"
          oauth:
            github_client_id: "Iv1.abc123def456"
            github_client_secret: "ghsecret_abcdefghijklmnopqrstuvwxyz"
            google_client_id: "123456789-abc.apps.googleusercontent.com"
            google_client_secret: "GOCSPX-abcdefghijklmnop"
    """)
    write_file(base, "opt/webapp/config/secrets.yml", secrets_yml)

    # docker-compose.yml
    docker_compose = textwrap.dedent(f"""\
        version: '3.8'
        services:
          api:
            image: {co['domain'].split('.')[0]}/webapp-api:latest
            env_file: .env
            ports:
              - "3000:3000"
            depends_on:
              - redis
            restart: always

          worker:
            image: {co['domain'].split('.')[0]}/webapp-worker:latest
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
            command: redis-server --requirepass {db.get('redis', 'password')}
            volumes:
              - redis_data:/data
            restart: always

        volumes:
          redis_data:
    """)
    write_file(base, "opt/webapp/docker-compose.yml", docker_compose)

    # server.js (fake app)
    server_js = textwrap.dedent(f"""\
        // Fake -- just holds the port open
        const http = require('http');
        const server = http.createServer((req, res) => {{
            res.writeHead(200, {{'Content-Type': 'application/json'}});
            res.end(JSON.stringify({{status: 'ok', version: '2.4.1', env: 'production'}}));
        }});
        server.listen(3000, () => console.log('API server running on :3000'));
    """)
    write_file(base, "opt/webapp/server.js", server_js)

    # .git/config
    git_config = textwrap.dedent(f"""\
        [core]
            repositoryformatversion = 0
            filemode = true
        [remote "origin"]
            url = git@gitlab.internal:{co['domain'].split('.')[0]}/webapp.git
            fetch = +refs/heads/*:refs/remotes/origin/*
        [branch "main"]
            remote = origin
            merge = refs/heads/main
        [user]
            name = Deploy Bot
            email = deploy@{internal}
    """)
    write_file(base, "opt/webapp/.git/config", git_config)


def gen_db_configs(cfg, base):
    """Generate database credential files: .my.cnf, .pgpass."""
    creds = cfg.get("credentials", _default_credentials())
    db = creds.get("databases", {})

    # Root .my.cnf
    mycnf = textwrap.dedent(f"""\
        [client]
        user=root
        password={db.get('mysql_root', 'password')}
        host=localhost
    """)
    write_file(base, "root/.my.cnf", mycnf, mode=0o600)

    # dbadmin .pgpass
    pgpass = textwrap.dedent(f"""\
        10.0.1.50:5432:production:dbadmin:{db.get('postgres_prod', 'password')}
        10.0.1.60:5432:staging:dbadmin:staging_pg_pass
        localhost:5432:*:postgres:local_pg_admin
    """)
    write_file(base, "home/dbadmin/.pgpass", pgpass, mode=0o600)


def gen_jenkins(cfg, base):
    """Generate Jenkins credentials files."""
    creds = cfg.get("credentials", _default_credentials())
    jenkins = creds.get("jenkins", {})

    master_key = jenkins.get("master_key", "0" * 64)
    write_file(base, "var/lib/jenkins/secrets/master.key", master_key + "\n", mode=0o600)

    credentials_xml = textwrap.dedent(f"""\
        <?xml version='1.0' encoding='UTF-8'?>
        <credentials>
          <entry>
            <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
              <id>prod-deploy</id>
              <username>deploy</username>
              <password>{jenkins.get('deploy_pass', 'password')}</password>
            </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
          </entry>
          <entry>
            <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
              <id>github-bot</id>
              <username>company-bot</username>
              <password>{jenkins.get('github_token', 'ghp_...')}</password>
            </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
          </entry>
        </credentials>
    """)
    write_file(base, "var/lib/jenkins/credentials.xml", credentials_xml)


def gen_vault(cfg, base):
    """Generate HashiCorp Vault token files."""
    creds = cfg.get("credentials", _default_credentials())
    vault = creds.get("vault", {})

    write_file(base, "root/.vault-token", vault.get("token", "hvs.FAKE") + "\n", mode=0o600)

    vault_profile = textwrap.dedent(f"""\
        export VAULT_ADDR="{vault.get('addr', 'https://vault.internal:8200')}"
        export VAULT_TOKEN="{vault.get('token', 'hvs.FAKE')}"
    """)
    write_file(base, "etc/profile.d/vault.sh", vault_profile)


def gen_ansible(cfg, base):
    """Generate Ansible inventory and group_vars."""
    creds = cfg.get("credentials", _default_credentials())
    db = creds.get("databases", {})
    app = creds.get("app", {})

    inventory = textwrap.dedent(f"""\
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
        ansible_become_password={app.get('ansible_sudo', 'password')}
    """)
    write_file(base, "opt/ansible/inventory/production", inventory)

    group_vars = textwrap.dedent(f"""\
        ---
        # Ansible vault password: {app.get('vault_master', 'password')}
        db_root_password: "{db.get('mysql_root', 'password')}"
        redis_password: "{db.get('redis', 'password')}"
        api_secret_key: "{app.get('jwt_secret', 'secret')}"
        smtp_password: "{app.get('sendgrid_key', 'SG...')}"
        slack_webhook: "https://FAKE-HONEYPOT-SLACK-WEBHOOK-NOT-REAL"
        backup_s3_bucket: "company-prod-backups"
        ssl_cert_path: "/etc/nginx/ssl/server.crt"
        ssl_key_path: "/etc/nginx/ssl/server.key"
    """)
    write_file(base, "opt/ansible/group_vars/all.yml", group_vars)


def gen_nginx_config(cfg, base):
    """Generate nginx site config and welcome page."""
    co = cfg["company"]
    internal = co.get("internal_domain", "company-internal.com")

    site_conf = textwrap.dedent(f"""\
        upstream api_backend {{
            server 127.0.0.1:3000;
            server 10.0.1.51:3000 backup;
        }}

        server {{
            listen 80;
            server_name api.{internal};
            return 301 https://$server_name$request_uri;
        }}

        server {{
            listen 443 ssl;
            server_name api.{internal};

            ssl_certificate /etc/nginx/ssl/server.crt;
            ssl_certificate_key /etc/nginx/ssl/server.key;

            location / {{
                proxy_pass http://api_backend;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            }}

            location /admin {{
                proxy_pass http://api_backend;
                allow 10.0.0.0/8;
                allow 192.168.0.0/16;
                deny all;
            }}
        }}
    """)
    write_file(base, "etc/nginx/sites-enabled/webapp.conf", site_conf)

    # Welcome page
    welcome = textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html>
        <head>
            <title>{co['name']}</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                       display: flex; justify-content: center; align-items: center;
                       min-height: 100vh; margin: 0; background: #f5f5f5; }}
                .container {{ text-align: center; padding: 2em; }}
                h1 {{ color: #333; font-size: 2em; }}
                p {{ color: #666; font-size: 1.1em; }}
                .domain {{ color: #0066cc; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>{co['name']}</h1>
                <p>{co.get('tagline', 'Production Server')}</p>
                <p class="domain">{co['domain']}</p>
                <hr>
                <p style="font-size: 0.9em; color: #999;">
                    {co.get('city', '')}, {co.get('state', '')} |
                    Contact: {co.get('contact_email', f"ops@{co['domain']}")}
                </p>
            </div>
        </body>
        </html>
    """)
    write_file(base, "var/www/html/index.html", welcome)


def gen_systemd_services(cfg, base):
    """Generate systemd service files."""
    services = cfg.get("services", _default_services())
    creds = cfg.get("credentials", _default_credentials())
    aws = creds.get("aws", {})
    aws_default = next((p for p in aws.get("profiles", []) if p["name"] == "default"), {})

    for svc in services:
        svc_type = svc.get("type", "simple")
        if svc_type == "oneshot":
            systemd_type = "oneshot"
        else:
            systemd_type = "simple"

        after = svc.get("after", "network.target")
        user = svc.get("user", "root")
        exec_cmd = svc.get("exec", "/bin/true")

        env_lines = ""
        # Add AWS env to backup services
        if "backup" in svc["name"].lower():
            env_lines = (
                f"Environment=AWS_ACCESS_KEY_ID={aws_default.get('access_key', 'AKIA...')}\n"
                f"Environment=AWS_SECRET_ACCESS_KEY={aws_default.get('secret_key', 'secret')}\n"
            )

        unit = textwrap.dedent(f"""\
            [Unit]
            Description={svc.get('description', svc['name'])}
            After={after}

            [Service]
            Type={systemd_type}
            User={user}
            ExecStart={exec_cmd}
            {env_lines}{"Restart=always" if systemd_type != "oneshot" else ""}
            {"RestartSec=10" if systemd_type != "oneshot" else ""}

            [Install]
            WantedBy=multi-user.target
        """)
        # Clean up empty lines from conditional fields
        unit = "\n".join(l for l in unit.split("\n") if l.strip() or l == "")
        write_file(base, f"etc/systemd/system/{svc['name']}.service", unit)


def gen_backup_scripts(cfg, base):
    """Generate fake backup and deploy scripts."""
    creds = cfg.get("credentials", _default_credentials())
    db = creds.get("databases", {})

    backup_sh = textwrap.dedent(f"""\
        #!/bin/bash
        # Daily database backup -- runs at 2am via cron
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        BACKUP_DIR="/opt/backups"

        # MySQL
        mysqldump -u root -p'{db.get('mysql_root', 'password')}' -h 10.0.1.50 --all-databases > "$BACKUP_DIR/mysql_full_$TIMESTAMP.sql"

        # PostgreSQL
        PGPASSWORD="{db.get('postgres_prod', 'password')}" pg_dump -h 10.0.1.50 -U dbadmin production > "$BACKUP_DIR/pg_prod_$TIMESTAMP.sql"

        # Compress and upload to S3
        tar czf "$BACKUP_DIR/backup_$TIMESTAMP.tar.gz" "$BACKUP_DIR"/*.sql
        aws s3 cp "$BACKUP_DIR/backup_$TIMESTAMP.tar.gz" s3://company-prod-backups/daily/

        # Cleanup old backups
        find "$BACKUP_DIR" -name "*.sql" -mtime +7 -delete
        find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete

        echo "Backup complete: $TIMESTAMP"
    """)
    write_file(base, "root/scripts/backup.sh", backup_sh, executable=True)

    deploy_sh = textwrap.dedent("""\
        #!/bin/bash
        # Production deployment script
        cd /opt/webapp
        git pull origin main
        docker-compose build --no-cache
        docker-compose down
        docker-compose up -d
        sleep 5
        curl -sf http://localhost:3000/health || echo "DEPLOY FAILED"
        curl -X POST -H "Content-Type: application/json" \\
            -d '{"text":"Production deployed by '"$(whoami)"' at '"$(date)"'"}' \\
            "https://FAKE-HONEYPOT-SLACK-WEBHOOK-NOT-REAL"
    """)
    write_file(base, "root/scripts/deploy.sh", deploy_sh, executable=True)


def gen_crontab(cfg, base):
    """Generate root crontab."""
    co = cfg["company"]
    internal = co.get("internal_domain", "company-internal.com")

    crontab = textwrap.dedent(f"""\
        # Database backup -- daily 2am
        0 2 * * * /root/scripts/backup.sh >> /var/log/backup.log 2>&1

        # SSL cert renewal -- weekly
        0 4 * * 0 certbot renew --quiet --post-hook "systemctl reload nginx"

        # Cleanup temp files
        0 6 * * * find /tmp -type f -mtime +3 -delete

        # System updates -- monthly
        0 3 1 * * apt update && apt upgrade -y >> /var/log/auto-update.log 2>&1

        # Monitoring heartbeat
        */5 * * * * curl -sf https://heartbeat.{internal}/ping/abc-123-def || true
    """)
    write_file(base, "var/spool/cron/crontabs/root", crontab, mode=0o600)


def gen_deploy_script(cfg, base):
    """Generate the master deploy.sh that installs everything on the target VM."""
    co = cfg["company"]
    users = cfg.get("users", _default_users())
    user_names = " ".join(u["name"] for u in users if u.get("role") not in ("service",))

    script = textwrap.dedent(f"""\
        #!/bin/bash
        # Master deployment script for cover story: {co['name']}
        # SCP this entire output directory to the sacrificial VM, then run this script as root.
        #
        # Usage:
        #   scp -r -J lepots@192.168.40.3:64295 /tmp/cover_output/ root@192.168.40.99:/tmp/cover/
        #   ssh -J lepots@192.168.40.3:64295 root@192.168.40.99 'bash /tmp/cover/deploy.sh'

        set -e
        COVER_DIR="$(cd "$(dirname "$0")" && pwd)"

        echo "=== Deploying Cover Story: {co['name']} ==="

        # Set hostname
        hostnamectl set-hostname {co.get('hostname', 'prod-01')}
        echo "{co.get('hostname', 'prod-01')}" > /etc/hostname

        # Create users
        bash "$COVER_DIR/scripts/create_users.sh"

        # Copy home directories
        if [ -d "$COVER_DIR/home" ]; then
            cp -a "$COVER_DIR/home/"* /home/ 2>/dev/null || true
        fi

        # Copy root files
        if [ -d "$COVER_DIR/root" ]; then
            cp -a "$COVER_DIR/root/"* /root/ 2>/dev/null || true
            cp -a "$COVER_DIR/root/".* /root/ 2>/dev/null || true
        fi

        # Copy etc files
        if [ -d "$COVER_DIR/etc" ]; then
            # MOTD
            [ -f "$COVER_DIR/etc/motd" ] && cp "$COVER_DIR/etc/motd" /etc/motd
            # Systemd services
            cp "$COVER_DIR/etc/systemd/system/"*.service /etc/systemd/system/ 2>/dev/null || true
            # Nginx
            mkdir -p /etc/nginx/sites-enabled /etc/nginx/ssl
            cp "$COVER_DIR/etc/nginx/sites-enabled/"* /etc/nginx/sites-enabled/ 2>/dev/null || true
            # Vault profile
            [ -f "$COVER_DIR/etc/profile.d/vault.sh" ] && cp "$COVER_DIR/etc/profile.d/vault.sh" /etc/profile.d/
            # Hosts — append, don't overwrite
            [ -f "$COVER_DIR/etc/hosts.append" ] && cat "$COVER_DIR/etc/hosts.append" >> /etc/hosts
        fi

        # Copy opt directories
        if [ -d "$COVER_DIR/opt" ]; then
            cp -a "$COVER_DIR/opt/"* /opt/ 2>/dev/null || true
        fi

        # Copy var directories
        if [ -d "$COVER_DIR/var" ]; then
            mkdir -p /var/lib/jenkins/secrets /var/spool/cron/crontabs /var/www/html
            cp -a "$COVER_DIR/var/"* /var/ 2>/dev/null || true
        fi

        # Setup SSH keys
        bash "$COVER_DIR/scripts/setup_ssh.sh"

        # Generate SSL cert
        bash "$COVER_DIR/scripts/gen_ssl.sh"

        # Fix permissions
        for user in {user_names}; do
            [ -d "/home/$user" ] && chown -R "$user:$user" "/home/$user" 2>/dev/null || true
        done
        chmod 600 /root/.my.cnf 2>/dev/null || true
        chmod 600 /root/.vault-token 2>/dev/null || true
        chmod 600 /home/dbadmin/.pgpass 2>/dev/null || true
        chown dbadmin:dbadmin /home/dbadmin/.pgpass 2>/dev/null || true
        chmod 600 /var/spool/cron/crontabs/root
        chown root:crontab /var/spool/cron/crontabs/root 2>/dev/null || true

        # Create required directories
        mkdir -p /opt/webapp/logs /opt/webapp/uploads /opt/backups /var/log/nginx

        # Reload systemd
        systemctl daemon-reload

        echo ""
        echo "=== Cover Story Deployed: {co['name']} ==="
        echo "Hostname: {co.get('hostname', 'prod-01')}"
        echo "Domain:   {co['domain']}"
        echo "Users:    {len(users)} accounts"
        echo "SSL CN:   {cfg.get('ssl', {}).get('cn', 'portal.' + co['domain'])}"
        echo ""
        echo "Next steps:"
        echo "  1. Verify with: hostname && cat /etc/motd"
        echo "  2. Check users: getent passwd | tail -20"
        echo "  3. Take a clean snapshot"
    """)
    write_file(base, "deploy.sh", script, executable=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate(cfg, output_dir):
    """Generate all cover story assets into output_dir."""
    base = Path(output_dir)
    if base.exists():
        print(f"[!] Output directory exists: {base}")
        print("    Files will be overwritten.")
    base.mkdir(parents=True, exist_ok=True)

    # Fill in defaults for optional sections
    if "users" not in cfg:
        cfg["users"] = _default_users()
    if "services" not in cfg:
        cfg["services"] = _default_services()
    if "network" not in cfg:
        cfg["network"] = _default_network()
    if "credentials" not in cfg:
        cfg["credentials"] = _default_credentials()

    co = cfg["company"]
    print(f"[*] Generating cover story: {co['name']}")
    print(f"    Domain:   {co['domain']}")
    print(f"    Hostname: {co.get('hostname', 'prod-01')}")
    print(f"    Users:    {len(cfg['users'])}")
    print(f"    Output:   {base}")
    print()

    gen_ssl_script(cfg, base)
    gen_etc_hosts(cfg, base)
    gen_motd(cfg, base)
    gen_users_script(cfg, base)
    gen_ssh_keys(cfg, base)
    gen_bash_histories(cfg, base)
    gen_aws_creds(cfg, base)
    gen_kube_config(cfg, base)
    gen_crypto_decoys(cfg, base)
    gen_webapp_configs(cfg, base)
    gen_db_configs(cfg, base)
    gen_jenkins(cfg, base)
    gen_vault(cfg, base)
    gen_ansible(cfg, base)
    gen_nginx_config(cfg, base)
    gen_systemd_services(cfg, base)
    gen_backup_scripts(cfg, base)
    gen_crontab(cfg, base)
    gen_deploy_script(cfg, base)

    print("[+] All assets generated.")
    print()
    print("To deploy:")
    print(f"  scp -r -J lepots@192.168.40.3:64295 {base}/ root@192.168.40.99:/tmp/cover/")
    print(f"  ssh -J lepots@192.168.40.3:64295 root@192.168.40.99 'bash /tmp/cover/deploy.sh'")


def main():
    parser = argparse.ArgumentParser(
        description="Generate cover story assets for ELKIE sacrificial VM honeypot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s --config cover_stories/default.yml --output /tmp/cover_output
              %(prog)s --from-env --output /tmp/cover_output
              %(prog)s --config cover_stories/my_company.yml -o /tmp/my_cover
        """)
    )
    parser.add_argument("--config", "-c", help="Path to YAML cover story config")
    parser.add_argument("--from-env", action="store_true", help="Build config from COVER_* env vars")
    parser.add_argument("--output", "-o", required=True, help="Output directory for generated assets")

    args = parser.parse_args()

    if not args.config and not args.from_env:
        parser.error("Must specify --config or --from-env")

    if args.config and args.from_env:
        parser.error("Specify either --config or --from-env, not both")

    if args.from_env:
        cfg = config_from_env()
    else:
        if not os.path.exists(args.config):
            print(f"ERROR: Config file not found: {args.config}", file=sys.stderr)
            sys.exit(1)
        cfg = load_config(args.config)

    generate(cfg, args.output)


if __name__ == "__main__":
    main()
