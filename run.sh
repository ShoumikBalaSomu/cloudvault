#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  CloudVault — Secure Cloud Storage Deployment Script
#  OS Security/Protection Project
#  This script sets up and runs the CloudVault application
#  on a Linux server with all required dependencies
# ═══════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

log_info()  { echo -e "${BLUE}[INFO]${NC}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_python() {
    log_info "Checking for Python 3..."
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
        log_ok "Found $(python3 --version)"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
        log_ok "Found $(python --version)"
    else
        log_error "Python 3 is not installed."
        log_info "Install it with: sudo apt install python3 python3-pip python3-venv"
        exit 1
    fi
}

setup_venv() {
    if [ ! -d "$PROJECT_DIR/venv" ]; then
        log_info "Creating virtual environment..."
        $PYTHON_CMD -m venv "$PROJECT_DIR/venv"
        log_ok "Virtual environment created."
    else
        log_warn "Virtual environment already exists."
    fi

    source "$PROJECT_DIR/venv/bin/activate"
    log_ok "Virtual environment activated."
}

install_deps() {
    log_info "Installing Python dependencies..."
    pip install --upgrade pip > /dev/null 2>&1
    pip install -r "$PROJECT_DIR/requirements.txt" > /dev/null 2>&1
    log_ok "Dependencies installed."
}

setup_admin() {
    log_info "Setting up admin account..."
    $PYTHON_CMD "$PROJECT_DIR/setup_admin.py"
}

create_storage() {
    if [ ! -d "$PROJECT_DIR/encrypted_storage" ]; then
        mkdir -p "$PROJECT_DIR/encrypted_storage"
        chmod 700 "$PROJECT_DIR/encrypted_storage"
        log_ok "Encrypted storage directory created (permissions: 700)."
    else
        log_warn "Storage directory already exists."
    fi
}

start_server() {
    log_info "Starting CloudVault server..."
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════${NC}"
    echo -e "${GREEN}  CloudVault is running!                    ${NC}"
    echo -e "${GREEN}  Open: http://localhost:5000               ${NC}"
    echo -e "${GREEN}  Admin: admin / admin123                   ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════${NC}"
    echo ""
    $PYTHON_CMD "$PROJECT_DIR/app.py"
}

deploy() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${BLUE}  CloudVault — Secure Cloud Storage         ${NC}"
    echo -e "${BLUE}  OS Security/Protection Project            ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo ""

    check_python
    setup_venv
    install_deps
    create_storage
    setup_admin

    echo ""
    log_ok "Deployment complete!"
    start_server
}

start() {
    check_python
    if [ -d "$PROJECT_DIR/venv" ]; then
        source "$PROJECT_DIR/venv/bin/activate"
    fi
    start_server
}

stop() {
    log_info "Stopping CloudVault..."
    pkill -f "python.*app.py" 2>/dev/null && log_ok "Server stopped." || log_warn "Server not running."
}

clean() {
    log_warn "This will remove the database, storage, and virtual environment."
    read -p "Are you sure? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        rm -rf "$PROJECT_DIR/venv"
        rm -rf "$PROJECT_DIR/encrypted_storage"
        rm -f "$PROJECT_DIR/cloudvault.db"
        log_ok "Cleanup complete."
    fi
}

case "${1:-help}" in
    deploy) deploy ;;
    start)  start  ;;
    stop)   stop   ;;
    clean)  clean  ;;
    *)
        echo "CloudVault — Run Script"
        echo "Usage: $0 {deploy|start|stop|clean}"
        echo ""
        echo "  deploy  — Full setup and start (first time)"
        echo "  start   — Start the server"
        echo "  stop    — Stop the server"
        echo "  clean   — Remove all data and reset"
        exit 1
        ;;
esac
