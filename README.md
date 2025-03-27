# Domain Health Checker

The Domain Health Checker monitors domain health across a wide set of security and reliability indicators. It performs regular checks, tracks historical changes, and sends alert emails when something shifts.

## ✅ Features

- HTTP & SSL status checks
- Mail records: SPF, DKIM, DMARC
- HTTP security headers
- Blacklist status
- WHOIS expiry and registrar info
- DNS details (A, AAAA, NS, reverse DNS)
- Tech stack detection (CMS/framework/server)
- Subdomain enumeration (Subfinder + Amass)
- Zone transfer vulnerability detection
- HTML and terminal output
- Diff-based alerting with color-coded reports
- Email alerts via SMTP (Gmail-compatible)
- Scheduled runs (cron/launchd)

---

## 🚀 Setup

```### 1. Clone and prepare environment

bash
git clone <repo-url>
cd domain-checker
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

2. Install Go tools

The install.sh script will install:
	•	Subfinder
	•	Amass

It will also help you schedule background scans.
chmod +x install.sh
./install.sh

It prompts:
	•	y to set up scheduled scans every 15 minutes
	•	u to uninstall scheduled jobs

Mac uses launchd. Linux uses cron.

🔒 Configuration

Create a .env file (if repo supports secrets separation):

EMAIL_SENDER=domainstatusalerts@gmail.com
EMAIL_PASSWORD=your_app_password
EMAIL_RECIPIENT=your_email@example.com

📬 Alerting

You will receive an email if any tracked fields change status (e.g., SSL days drop, DNS provider changes, domain gets blacklisted, etc).

HTML reports are saved in the reports/ folder. Diff logic runs off last_results.json.

⸻

⚙️ Uninstall / Reconfigure

Just re-run install.sh and choose u to uninstall the scheduled job. You can also reschedule anytime.

For fun here is a rap song!!

Yo, it’s the domain checker, steady on the grind,
Catchin’ SSL slips, keepin’ records in line.
DNS on the watch, headers tight like a vault,
If your SPF fails, you know who’s at fault.

Gimme that repo, git clone and ride,
Spin up a venv, take that code for a glide.
install.sh – yeah, that script’s the key,
Schedules the checks like it’s VIP.

No balloon valves, this thing don’t leak,
If your zone’s transferin’, we hear it squeak.
Subfinder, Amass, tools on deck,
With Go in the path, this stack gets respect.

Wanna know if your domain gonna blow?
HTML reports and a JSON flow.
Alerts by mail, we keep it stealth,
Notify change, protect that digital wealth.

15-minute scans? You bet it runs,
With launchd heat or Linux crons.
macOS got style, it shows the name,
No more “python3”, this job got game.

So Gary, plug it in and let it ride,
Your domains are covered, peace of mind on your side.
Just check your inbox when it’s goin’ down—
This checker don’t sleep, it wears the crown.
