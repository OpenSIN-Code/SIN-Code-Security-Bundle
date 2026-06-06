#!/bin/bash
set -e

echo "🎯 SIN-Code-Security-Bundle Setup"
echo "================================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 nicht gefunden."
    exit 1
fi

echo "✅ Python 3: $(python3 --version)"

# Check Go
if ! command -v go &> /dev/null; then
    echo "⚠️  Go nicht gefunden. Für CLI bitte installieren: https://go.dev/dl/"
else
    echo "✅ Go: $(go version)"
fi

# Create virtual environment
echo "📦 Erstelle virtuelle Umgebung..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "📦 Installiere Python-Dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install all sub-tools
echo "🔧 Installiere Security-Tools..."

# SCA Tool
echo "   📦 SCA Tool..."
pip install osv-scanner || echo "   ⚠️  osv-scanner optional"

# Container Tool
echo "   🐳 Container Tool..."
if ! command -v trivy &> /dev/null; then
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.50.1 || echo "   ⚠️  Trivy installation failed"
fi

# IaC Tool
echo "   🏗️  IaC Tool..."
pip install checkov || echo "   ⚠️  Checkov optional"

# License Tool
echo "   📜 License Tool..."
pip install scancode-toolkit || echo "   ⚠️  ScanCode optional"

# DAST Tool
echo "   🎯 DAST Tool..."
if command -v go &> /dev/null; then
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || echo "   ⚠️  Nuclei optional"
fi

# Build Go CLI
if command -v go &> /dev/null; then
    echo "🔨 Baue Go CLI..."
    make build
fi

echo ""
echo "✅ Setup abgeschlossen!"
echo ""
echo "📖 Nächste Schritte:"
echo "   1. Aktiviere venv: source venv/bin/activate"
echo "   2. Starte MCP Server: python src/server.py"
echo "   3. Oder nutze CLI: ./bin/sin-security scan ./project --full"
echo ""
echo "🎯 Beispiel-Scans:"
echo "   sin-security scan ./my-project --full"
echo "   sin-security compliance ./my-project --frameworks cis,nist"
echo "   sin-security executive-report ./my-project --format pdf"
echo ""
