#!/bin/bash

echo "🔧 Installing system dependencies..."

# Check for Go
if ! command -v go &> /dev/null; then
  echo "⚠️ Go is not installed. Please install Go from https://golang.org/dl/ and re-run this script."
  exit 1
fi

# Add Go to PATH if needed
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
  echo "⚙️ Adding ~/go/bin to PATH (will apply on next shell restart)"
  echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zprofile
fi

# Install Go tools
echo "📦 Installing subfinder..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "📦 Installing amass..."
go install github.com/owasp-amass/amass/v3/...@latest

# Python dependencies
echo "🐍 Installing Python dependencies..."
pip install -r requirements.txt

echo "✅ Setup complete."

# Ask about job setup
echo
read -p "🕒 Do you want to set up a scheduled scan job now? (y/n/u for uninstall): " job_choice

script_path="$(pwd)/main.py"
python_path="$(which python3)"

if [[ "$job_choice" == "y" ]]; then
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS launchd setup
    plist_file="$HOME/Library/LaunchAgents/com.domainchecker.job.plist"
    cat > "$plist_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.domainchecker.job</string>
  <key>ProgramArguments</key>
  <array>
    <string>$python_path</string>
    <string>$script_path</string>
    <string>--from-csv</string>
  </array>
  <key>StartInterval</key>
  <integer>900</integer>
  <key>StandardOutPath</key>
  <string>$HOME/domainchecker.log</string>
  <key>StandardErrorPath</key>
  <string>$HOME/domainchecker.err</string>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
EOF

    launchctl bootout gui/$(id -u) "$plist_file" &>/dev/null
    launchctl bootstrap gui/$(id -u) "$plist_file"
    echo "📅 macOS job scheduled via launchd."

  else
    # Linux cron job
    (crontab -l 2>/dev/null | grep -v "$script_path"; echo "*/15 * * * * $python_path $script_path --from-csv >> \$HOME/domainchecker.log 2>&1") | crontab -
    echo "📅 Linux job scheduled via crontab."
  fi

elif [[ "$job_choice" == "u" ]]; then
  if [[ "$OSTYPE" == "darwin"* ]]; then
    plist_file="$HOME/Library/LaunchAgents/com.domainchecker.job.plist"
    launchctl bootout gui/$(id -u) "$plist_file" &>/dev/null
    rm -f "$plist_file"
    echo "🗑️ Removed scheduled job on macOS."
    echo "🔁 You may need to log out or reboot to remove background item from UI."
  else
    crontab -l | grep -v "$script_path" | crontab -
    echo "🗑️ Removed scheduled job from Linux crontab."
  fi

else
  echo "ℹ️ Skipping job setup. You can re-run this script later to install/uninstall the job."
fi
