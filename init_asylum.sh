#!/bin/bash

set -eE

# Modalità debug
DEBUG=false
[[ "$1" == "--debug" ]] && DEBUG=true

# Messaggio di avvio
if $DEBUG; then
  echo -e "📢 Modalità DEBUG attiva. Verrà mostrato tutto l'output dei comandi."
else
  echo -e "📢 Usa '--debug' per mostrare i dettagli in caso di errore."
fi

# Funzione di esecuzione condizionata
run() {
  if $DEBUG; then
    "$@"
  else
    "$@" >/dev/null 2>&1
  fi
}

# Rollback in caso di errore o interruzione
rollback() {
  echo -e "\n❌ Errore o interruzione: rollback in corso..."
  docker-compose -f /opt/asylum/docker-compose.yml down || true
  docker network rm asylum_net || true
  rm -rf /opt/asylum
  echo "🔁 Rollback completato."
  exit 1
}

trap rollback ERR INT

function progress() {
  local message="$1"
  printf "%-38s" "$message"
  for i in {1..20}; do
    printf "●"
    sleep 0.05
  done
  echo " ✅"
}

# Aggiornamento e installazione dipendenze
progress "🔧 Verifica/Installazione dipendenze..."
run apt-get update -qq
run apt-get install -y -qq git curl docker.io docker-compose openssl

# Creazione della struttura di cartelle
progress "📁 Preparazione struttura.............."
mkdir -p /opt/asylum
cd /opt/asylum

# Download del docker-compose.yml
progress "📥 Download docker-compose.yml........."
run curl -fsSL https://raw.githubusercontent.com/NeverTheDogs/asylum/main/docker-compose.yml -o docker-compose.yml

# Controllo delle variabili di configurazione
if ! grep -q "WAZUH_MANAGER_PASSWORD" docker-compose.yml || ! grep -q "WAZUH_API_PASSWORD" docker-compose.yml; then
  echo "❌ Le variabili WAZUH_MANAGER_PASSWORD e WAZUH_API_PASSWORD non sono presenti nel file docker-compose.yml!"
  rollback
fi

# Creazione della rete Docker
progress "🌐 Creazione rete Docker..............."
run docker network create --driver bridge asylum_net || true

# Generazione certificati TLS autofirmati
progress "🔐 Generazione certificati TLS........."
mkdir -p certs
run openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout certs/key.pem -out certs/cert.pem \
  -subj "/CN=asylum.local"

# Avvio dello stack di sicurezza
progress "🚀 Avvio stack di sicurezza............"
run docker-compose up -d

# Verifica che i servizi siano attivi
progress "🔍 Verifica servizi attivi............."
if ! docker ps --format "{{.Names}}" | grep -qE "wazuh-manager|elasticsearch|logstash|shuffle"; then
  rollback
fi

echo -e "\n✅ Stack installato correttamente e in esecuzione!"
