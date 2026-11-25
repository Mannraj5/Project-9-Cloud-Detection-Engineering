# SIEM setup (Elastic in WSL2)

The SIEM runs locally, so it costs nothing. It runs in Ubuntu on WSL2 on a Windows PC.
Check Elastic's current docs before you start, because the install script and licence
terms can change.

## Why WSL2 and not VirtualBox

The first plan was an Ubuntu Server VM in VirtualBox. With Windows Memory Integrity (core
isolation) turned on, Windows keeps VT-x for its own hypervisor and VirtualBox falls back
to a slow compatibility mode (its log says `VT-x is not available ... fall back to NEM`).
The Ubuntu installer hung at "Loading essential drivers". WSL2 runs on the same Windows
hypervisor, so it works with Memory Integrity left on, and turning off a host security
control for a lab is a poor trade.

## 1. WSL2 and Ubuntu

In an admin PowerShell, then restart Windows:

```powershell
wsl --install --no-distribution
```

Cap WSL's memory in `%USERPROFILE%\.wslconfig` so Elastic can't starve the host
(Elasticsearch and Kibana together need about 4 GB):

```ini
[general]
instanceIdleTimeout=-1

[wsl2]
memory=8GB
processors=4
swap=4GB
vmIdleTimeout=-1
```

The two idle timeouts matter. By default WSL stops a distro soon after its last terminal
closes, which stops Docker and Elastic with it. With `-1` it keeps running until
`wsl --shutdown` or a reboot.

Install Ubuntu off the system drive:

```powershell
wsl --install Ubuntu-26.04 --location D:\WSL\Ubuntu-26.04
```

Ubuntu on WSL has systemd on by default (`/etc/wsl.conf`), and `vm.max_map_count` is
already high enough for Elasticsearch.

## 2. Docker and Elastic start-local

Install Docker Engine inside Ubuntu from Docker's apt repository (see Docker's "Install
Docker Engine on Ubuntu" page; Docker Desktop isn't needed). Then download Elastic's
`start-local` script, read it, and run it. It sets up Elasticsearch and Kibana in Docker
with security on, for local development:

```bash
curl -fsSL https://elastic.co/start-local -o start-local.sh
less start-local.sh
sh start-local.sh
```

Make the containers come back whenever Docker starts (start-local doesn't set a restart
policy):

```bash
docker update --restart unless-stopped es-local-dev kibana-local-dev
```

start-local publishes ports 9200 and 5601 on 127.0.0.1 only. WSL2 forwards localhost to Windows, so
Kibana and Elasticsearch open on `localhost` from the PC and nothing is exposed to the
network.

The script creates an `elastic-start-local/` folder. Its `.env` file holds the `elastic`
password and an API key. Treat that file as a secret: it is in `.gitignore`, and nothing in
it goes in the repo or in screenshots.

It starts a 30-day trial and then drops to the free Basic licence. At the time of writing,
detection rules (including ES|QL rules) work on Basic. Check Elastic's subscriptions page.

Open Kibana at http://localhost:5601 and sign in as `elastic`.

## 3. Connect detlab

On the Windows PC (WSL2 forwards localhost) or inside Ubuntu:

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

Kibana 9 can open the Default space in the "Elasticsearch" solution view, which turns the
Security app off (`/app/security/rules` says "Application not found"). Switch it first:
gear icon → **Spaces → Default → Solution view: Security → Apply changes**.

In Kibana go to **Security → Rules → Detection rules → Import rules** and import
`build/kibana-rules.ndjson`. The rules arrive enabled with a 10-minute schedule (see
`design-notes.md` for why). Imported rules need a user with Security privileges; `elastic`
has them.

Also create a data view for `detlab-*` (Stack Management → Data views) so you can browse the
events in Discover.

## 5. Back it up

Once Elastic is running and the rules are imported, export the distro as a restore point.
If something breaks during testing, restore it instead of debugging for an hour:

```powershell
wsl --shutdown
wsl --export Ubuntu-26.04 D:\WSL\backups\ubuntu-elastic-ready.tar
# restore: wsl --import Ubuntu-26.04 D:\WSL\Ubuntu-26.04 D:\WSL\backups\ubuntu-elastic-ready.tar
```

Stop Elastic when you're not using it (`elastic-start-local/stop.sh`, or `wsl --shutdown`)
to get the 8 GB back.
