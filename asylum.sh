#!/bin/bash
set -euo pipefail

#source "$(dirname "$0")/config.sh"
source "$(dirname "$0")/lib/functions.sh"

# Aggiorna e installa i prerequisiti
log_info "Aggiornamento del sistema e installazione prerequisiti..."
apt-get update && apt-get upgrade -y
apt-get install -y curl gnupg apt-transport-https lsb-release ca-certificates debhelper tar libcap2-bin git unzip yq

# Estrazione dei parametri dal file di configurazione
CONFIG_FILE="config/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
  log_error "File di configurazione non trovato: $CONFIG_FILE"
  exit 1
fi
NODE_NAME=$(yq e '.NODE_NAME' "$CONFIG_FILE")
WAZUH_USER=$(yq e '.WAZUH_USER' "$CONFIG_FILE")
WAZUH_PASS=$(yq e '.WAZUH_PASS' "$CONFIG_FILE")
WAZUH_SERVER_IP=$(yq e '.WAZUH_SERVER_IP' "$CONFIG_FILE")
FILEBEAT_DEB=$(yq e '.FILEBEAT_DEB' "$CONFIG_FILE")
GPG_KEY_URL=$(yq e '.GPG_KEY_URL' "$CONFIG_FILE")
WAZUH_REPO_URL=$(yq e '.WAZUH_REPO_URL' "$CONFIG_FILE")
WAZUH_CERT_TOOL=$(yq e '.WAZUH_CERT_TOOL' "$CONFIG_FILE")
WAZUH_CERT_CONFIG=$(yq e '.WAZUH_CERT_CONFIG' "$CONFIG_FILE")
CERT_ARCHIVE=$(yq e '.CERT_ARCHIVE' "$CONFIG_FILE")

# Display del menù iniziale
menu_main() {
  clear
  check_root
  while true; do
    echo "=================================================="
    echo "|                 Gestione progetto                |"
    echo "=================================================="
    echo "1) Installa progetto"
    echo "2) Rimuovi progetto"
    echo "99) TEST"
    echo "0) Esci"
    echo "--------------------------------------------------"
    read -rp "Seleziona un'opzione: " option
    case "$option" in
      1)
        log_info "Avvio installazione di Wazuh..."
        installEverything
        exit 0
        ;;
      2)
        log_info "Avvio rimozione di Wazuh..."
        removeEverything
        exit 0
        ;;
      0)
        log_info "Uscita."
        exit 0
        ;;
      99)
        log_info "Esecuzione funzione di test"
        #install_Jira
        exit 0
        ;;
      *)
        log_warning "Opzione non valida. Riprova."
        ;;
    esac
  done
}

menu_main