#!/bin/bash

# CTF Toolkit Setup Script
# Télécharge et configure les wordlists et outils nécessaires

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLISTS_DIR="$SCRIPT_DIR/wordlists"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║       CTF Toolkit Setup Script        ║"
echo "╚═══════════════════════════════════════╝"
echo ""

# Création du dossier wordlists si nécessaire
mkdir -p "$WORDLISTS_DIR/custom"

# ===================
# SecLists
# ===================
install_seclists() {
    if [ -d "$WORDLISTS_DIR/seclists" ]; then
        print_warning "SecLists déjà présent. Mise à jour..."
        cd "$WORDLISTS_DIR/seclists"
        git pull --quiet
        print_success "SecLists mis à jour"
    else
        print_status "Téléchargement de SecLists (peut prendre quelques minutes)..."
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLISTS_DIR/seclists"
        print_success "SecLists installé"
    fi
}

# ===================
# Rockyou
# ===================
install_rockyou() {
    ROCKYOU_DIR="$WORDLISTS_DIR/rockyou"
    ROCKYOU_FILE="$ROCKYOU_DIR/rockyou.txt"

    if [ -f "$ROCKYOU_FILE" ]; then
        print_warning "rockyou.txt déjà présent"
        return
    fi

    mkdir -p "$ROCKYOU_DIR"
    print_status "Téléchargement de rockyou.txt..."

    # Téléchargement depuis le repo SecLists (version compressée)
    ROCKYOU_URL="https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"

    if command -v curl &> /dev/null; then
        curl -L -o "$ROCKYOU_FILE" "$ROCKYOU_URL" --progress-bar
    elif command -v wget &> /dev/null; then
        wget -q --show-progress -O "$ROCKYOU_FILE" "$ROCKYOU_URL"
    else
        print_error "curl ou wget requis pour télécharger rockyou"
        return 1
    fi

    print_success "rockyou.txt installé ($(du -h "$ROCKYOU_FILE" | cut -f1))"
}

# ===================
# Menu principal
# ===================
case "${1:-all}" in
    seclists)
        install_seclists
        ;;
    rockyou)
        install_rockyou
        ;;
    all)
        install_seclists
        install_rockyou
        ;;
    *)
        echo "Usage: $0 {all|seclists|rockyou}"
        exit 1
        ;;
esac

echo ""
print_success "Setup terminé !"
echo ""
echo "Structure des wordlists:"
ls -la "$WORDLISTS_DIR" 2>/dev/null || true
echo ""
