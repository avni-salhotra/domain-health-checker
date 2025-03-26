#!/bin/bash

echo "🔧 Installing system dependencies..."

# Install Go if it's not installed
if ! command -v go &> /dev/null; then
  echo "⚠️ Go is not installed. Please install Go from https://golang.org/dl/ and re-run this script."
  exit 1
fi

# Add Go bin to PATH if needed
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
  echo "⚙️ Adding ~/go/bin to PATH (will apply on next shell restart)"
  echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zprofile
fi

echo "📦 Installing subfinder..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "📦 Installing amass..."
go install github.com/owasp-amass/amass/v3/...@latest

echo "🐍 Installing Python dependencies..."
pip install -r requirements.txt

echo "✅ Setup complete. Restart your shell or run:"
echo "    export PATH=\$PATH:\$HOME/go/bin"
