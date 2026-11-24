# SIEM setup (Elastic in a VirtualBox VM)

The SIEM runs locally, so it costs nothing. These steps were written for an Ubuntu Server
VM. Check Elastic's current docs before you start, because the install script and licence
terms can change.

## 1. VM

- Ubuntu Server 24.04 LTS, 2 vCPU, **8 GB RAM** (Elasticsearch and Kibana together need
  about 4 GB; 8 GB stays responsive), 40 GB disk.
- Networking: NAT plus a port forward for 5601 (Kibana) and 9200 (Elasticsearch) to
  127.0.0.1 on the host only. Don't bridge it onto the university or home network.
- Take a snapshot after the OS install.

## 2. Docker and Elastic start-local

Elastic's `start-local` script sets up Elasticsearch and Kibana in Docker with security on,
for local development:

```bash
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 curl
sudo usermod -aG docker "$USER"   # log out and back in after this
curl -fsSL https://elastic.co/start-local | sh
```

The script creates an `elastic-start-local/` folder. Its `.env` file holds the `elastic`
password and an API key. Treat that file as a secret: it is in `.gitignore`, and nothing in
it goes in the repo or in screenshots.

It starts a 30-day trial and then drops to the free Basic licence. At the time of writing,
detection rules (including ES|QL rules) work on Basic. Check Elastic's subscriptions page.

Open Kibana at http://localhost:5601 and sign in as `elastic`.

## 3. Connect detlab

On the machine that will run `detlab` (the VM, or your PC through the port forward):

```bash
python -m venv .venv
. .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
export ES_URL=http://localhost:9200
export ES_API_KEY=...          # from elastic-start-local/.env (ES_LOCAL_API_KEY)
detlab live-validate           # runs every fixture against your cluster (detlabtest-* only)
```

PowerShell uses `$env:ES_URL = "http://localhost:9200"` and `$env:ES_API_KEY = "..."`.
Don't put the key in a script file you might commit.

## 4. Load the rules into Elastic Security

```bash
detlab kibana -o build/kibana-rules.ndjson
```

In Kibana go to **Security → Rules → Detection rules → Import rules** and import
`build/kibana-rules.ndjson`. The rules arrive enabled with a 10-minute schedule (see
`design-notes.md` for why). Imported rules need a user with Security privileges; `elastic`
has them.

Also create a data view for `detlab-*` (Stack Management → Data views) so you can browse the
events in Discover.

## 5. Snapshot again

Snapshot the VM once Elastic is running and the rules are imported. If something breaks
during testing, roll back instead of debugging for an hour.
