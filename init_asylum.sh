#!/bin/bash

set -e

# Rollback in caso di errore
rollback() {
  echo -e "\n❌ Errore: rollback in corso..."
  docker-compose -f /opt/asylum/docker-compose.yml down || true
  docker network rm asylum_net || true
  rm -rf /opt/asylum
  echo "Rollback completato."
  exit 1
}

trap rollback ERR

function progress() {
  local message="$1"
  printf "%-38s" "$message"
  for i in {1..20}; do
    printf "●"
    sleep 0.05
  done
  echo " ✅"
}

progress "🔧 Verifica/Installazione dipendenze..."
apt-get update -qq
apt-get install -y -qq git curl docker.io docker-compose openssl

progress "📁 Preparazione struttura.............."
mkdir -p /opt/asylum
cd /opt/asylum

progress "📥 Download docker-compose.yml........."
curl -fsSL https://raw.githubusercontent.com/NeverTheDogs/asylum/main/docker-compose.yml -o docker-compose.yml

# Controllo variabili
if ! grep -q "WAZUH_MANAGER_PASSWORD" docker-compose.yml || ! grep -q "WAZUH_API_PASSWORD" docker-compose.yml; then
  echo "❌ Le variabili WAZUH_MANAGER_PASSWORD e WAZUH_API_PASSWORD non sono presenti nel file docker-compose.yml!"
  rollback
fi

progress "🌐 Creazione rete Docker..............."
docker network create --driver bridge asylum_net || true

progress "🔐 Generazione certificati TLS........."
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout certs/key.pem -out certs/cert.pem \
  -subj "/CN=asylum.local" >/dev/null 2>&1

progress "🚀 Avvio stack di sicurezza............"
docker-compose up -d >/dev/null 2>&1

progress "🔍 Verifica servizi attivi............."
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "wazuh|zeek|elasticsearch|thehive|shuffle" >/dev/null || rollback

echo -e "\n✅ Stack installato correttamente e in esecuzione!"
