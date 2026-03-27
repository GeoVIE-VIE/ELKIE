# Cover Story Generator

Generates a complete set of honeypot decoy files from a YAML config or environment variables. Output is a directory tree ready to SCP to the sacrificial VM.

## Requirements

```
pip3 install pyyaml
```

## Usage

### From YAML config (recommended)

```bash
python3 generate_cover.py --config cover_stories/default.yml --output /tmp/cover_output
```

### From environment variables

Set the `COVER_*` vars in your `.env` or `.sample_analyzer_env`, then:

```bash
source /home/legs/.env
python3 generate_cover.py --from-env --output /tmp/cover_output
```

### Deploy to sacrificial VM

```bash
# SCP through T-Pot jump host
scp -r -J lepots@192.168.40.3:64295 /tmp/cover_output/ root@192.168.40.99:/tmp/cover/

# Run the deploy script on the VM
ssh -J lepots@192.168.40.3:64295 root@192.168.40.99 'bash /tmp/cover/deploy.sh'
```

**Remember:** Always revert to a clean snapshot before deploying a new cover story, then take a fresh snapshot after deployment.

## Creating a custom cover story

1. Copy the example template:
   ```bash
   cp cover_stories/example.yml cover_stories/my_company.yml
   ```

2. Edit company info, users, credentials, and services.

3. Generate and deploy:
   ```bash
   python3 generate_cover.py -c cover_stories/my_company.yml -o /tmp/my_cover
   ```

## What gets generated

| Path | Contents |
|------|----------|
| `deploy.sh` | Master install script (run on target VM) |
| `scripts/` | SSL cert gen, user creation, SSH key setup |
| `etc/motd` | Login banner with company branding |
| `etc/hosts.append` | Fake internal DNS entries |
| `etc/nginx/` | Site config with upstream proxy |
| `etc/systemd/system/` | Fake service unit files |
| `etc/profile.d/vault.sh` | Vault env vars |
| `home/*/` | Bash histories, SSH keys, AWS/K8s/crypto configs |
| `opt/webapp/` | .env, database.yml, secrets.yml, docker-compose, .git |
| `opt/ansible/` | Inventory and group_vars with passwords |
| `var/lib/jenkins/` | credentials.xml and master.key |
| `var/www/html/` | Branded welcome page |
| `root/` | .my.cnf, .vault-token, backup/deploy scripts |

## Files

- `cover_stories/default.yml` -- Current Dirigo Systems LLC config
- `cover_stories/example.yml` -- Documented template for new identities
