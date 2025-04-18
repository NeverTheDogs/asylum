#!/bin/bash

# Configurazioni
CERTS_DIR="/home/kaarl/Scrivania/asylum/certs"
DOCKER_COMPOSE_FILE="docker-compose.yml"
DEBUG_MODE=false
ELASTIC_IMAGE="docker.elastic.co/elasticsearch/elasticsearch:7.17.3"
KIBANA_IMAGE="docker.elastic.co/kibana/kibana:7.17.3"
LOGSTASH_IMAGE="docker.elastic.co/logstash/logstash:7.17.3"
WAZUH_IMAGE="wazuh/wazuh-manager:4.4.0"
NETWORK_NAME="asylum_network"

# Gestione dei segnali: se viene interrotto lo script (CTRL+C o SIGTERM) esegue il rollback.
trap rollback INT TERM

# Funzione di rollback: arresta i container e rimuove eventuali residui, incluso il network.
rollback() {
  echo -e "\n[ERROR] Rollback in corso... Ripristino dello stato iniziale."
  
  # Tenta di fermare i container e rimuovere network e volumi
  docker-compose down --remove-orphans --volumes || echo "[WARN] docker-compose down non ha terminato tutti i container."

  # Rimozione forzata dei container (se presenti)
  for container in elasticsearch kibana logstash wazuh; do
    if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
      echo "[INFO] Rimozione forzata del container ${container}"
      docker rm -f "${container}" 2>/dev/null || true
    fi
  done
  
  # Tentativo di rimuovere manualmente il network specificato
  if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    endpoints=$(docker network inspect "$NETWORK_NAME" --format '{{range $id, $container := .Containers}}{{$id}} {{end}}')
    for ep in $endpoints; do
      echo "[INFO] Disconnetto il container $ep dalla rete $NETWORK_NAME"
      docker network disconnect "$NETWORK_NAME" "$ep" --force
    done
    echo "[INFO] Rimozione della rete $NETWORK_NAME"
    docker network rm "$NETWORK_NAME" || echo "[WARN] Impossibile rimuovere la rete $NETWORK_NAME"
  fi
  
  rm -f "$DOCKER_COMPOSE_FILE"
  rm -rf "$CERTS_DIR"
  
  echo "[INFO] Rollback completato. Esco."
  exit 1
}

# Controlla se sono installati i prerequisiti necessari
check_prerequisites() {
  command -v docker        >/dev/null || { echo "[ERROR] Docker non è installato. Installa Docker prima di continuare."; exit 1; }
  command -v docker-compose >/dev/null || { echo "[ERROR] docker-compose non è installato. Installa docker-compose prima di continuare."; exit 1; }
  command -v openssl       >/dev/null || { echo "[ERROR] OpenSSL non è installato. Installa OpenSSL prima di continuare."; exit 1; }
}

# Funzione per loggare i passaggi
log_step() {
  local message="$1"
  echo -e "[INFO] $message"
}

# Verifica se il file logstash.conf esiste; se non esiste, lo crea di default.
check_logstash_conf() {
  if [ ! -f "logstash.conf" ]; then
    log_step "File logstash.conf non trovato. Creo una configurazione di default."
    echo "# Logstash pipeline default configuration" > logstash.conf
  fi
}

# Abilita la modalità di debug se viene passato il flag --debug
if [[ "$1" == "--debug" ]]; then
  DEBUG_MODE=true
  set -x
fi

# Genera il file docker-compose.yml iniziale (modalità senza SSL)
generate_docker_compose_no_ssl() {
  log_step "Generazione del file Docker Compose senza SSL"
  cat > "$DOCKER_COMPOSE_FILE" <<EOL
version: "3.9"
services:
  elasticsearch:
    image: $ELASTIC_IMAGE
    container_name: elasticsearch
    restart: always
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=false
    ulimits:
      memlock:
        soft: -1
        hard: -1
    mem_limit: 1g
    ports:
      - "9200:9200"
    volumes:
      - ./certs:/usr/share/elasticsearch/config/certs
    networks:
      - asylum_network

  kibana:
    image: $KIBANA_IMAGE
    container_name: kibana
    restart: always
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    networks:
      - asylum_network

  logstash:
    image: $LOGSTASH_IMAGE
    container_name: logstash
    restart: always
    ports:
      - "5044:5044"
      - "5000:5000"
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
      - ./certs:/usr/share/logstash/config/certs
    depends_on:
      - elasticsearch
    networks:
      - asylum_network

  wazuh:
    image: $WAZUH_IMAGE
    container_name: wazuh
    restart: always
    environment:
      - ELASTICSEARCH_URL=http://elasticsearch:9200
    ports:
      - "1514:1514"
      - "1515:1515"
      - "55000:55000"
    networks:
      - asylum_network

volumes:
  elasticsearch-data:

networks:
  asylum_network:
    driver: bridge
    name: ${NETWORK_NAME}
EOL
}

# Genera i certificati SSL necessari e imposta i permessi in modo che il container possa leggerli.
generate_certificates() {
  local original_dir
  original_dir=$(pwd)
  
  log_step "Generazione dei certificati SSL in $CERTS_DIR"
  mkdir -p "$CERTS_DIR" || { echo "[ERROR] Impossibile creare la directory $CERTS_DIR"; exit 1; }
  cd "$CERTS_DIR" || { echo "[ERROR] Impossibile accedere alla directory $CERTS_DIR"; exit 1; }
  
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout elastic-key.pem -out elastic-cert.pem -subj "/CN=elasticsearch" > /dev/null 2>&1 || { echo "[ERROR] Errore nella generazione dei certificati"; exit 1; }
  
  openssl pkcs12 -export -out elastic-certificates.p12 -inkey elastic-key.pem -in elastic-cert.pem -passout pass: > /dev/null 2>&1 || { echo "[ERROR] Errore nella generazione del certificato PKCS#12"; exit 1; }
  
  # Modifica i permessi dei file per consentire al container Elasticsearch di leggere la chiave
  chmod 644 elastic-key.pem
  chmod 644 elastic-cert.pem
  chmod 644 elastic-certificates.p12
  
  log_step "Certificati generati e permessi impostati correttamente in $CERTS_DIR"
  cd "$original_dir" || exit 1
}

# Genera il file docker-compose.yml aggiornato per abilitare SSL
generate_docker_compose_with_ssl() {
  log_step "Aggiornamento del file Docker Compose per SSL con tutti i container"
  cat > "$DOCKER_COMPOSE_FILE" <<EOL
version: "3.9"
services:
  elasticsearch:
    image: $ELASTIC_IMAGE
    container_name: elasticsearch
    restart: always
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=true
      - xpack.security.http.ssl.key=/usr/share/elasticsearch/config/certs/elastic-key.pem
      - xpack.security.http.ssl.certificate=/usr/share/elasticsearch/config/certs/elastic-cert.pem
      - ELASTIC_PASSWORD=elastic
    ulimits:
      memlock:
        soft: -1
        hard: -1
    mem_limit: 1g
    ports:
      - "9200:9200"
    volumes:
      - ./certs:/usr/share/elasticsearch/config/certs
    networks:
      - asylum_network

  kibana:
    image: $KIBANA_IMAGE
    container_name: kibana
    restart: always
    environment:
      - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
      - ELASTICSEARCH_SSL_VERIFICATIONMODE=none
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=elastic
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    networks:
      - asylum_network

  logstash:
    image: $LOGSTASH_IMAGE
    container_name: logstash
    restart: always
    ports:
      - "5044:5044"
      - "5000:5000"
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
      - ./certs:/usr/share/logstash/config/certs
    depends_on:
      - elasticsearch
    networks:
      - asylum_network

  wazuh:
    image: $WAZUH_IMAGE
    container_name: wazuh
    restart: always
    environment:
      - ELASTICSEARCH_URL=https://elasticsearch:9200
    ports:
      - "1514:1514"
      - "1515:1515"
      - "55000:55000"
    networks:
      - asylum_network

volumes:
  elasticsearch-data:

networks:
  asylum_network:
    driver: bridge
    name: ${NETWORK_NAME}
EOL
}

# Riavvia i container applicando la nuova configurazione (SSL abilitato)
restart_with_ssl() {
  log_step "Riavvio dei container Docker con configurazione SSL"
  docker-compose down --remove-orphans --volumes || rollback

  # Forza la rimozione dei container residui se ancora presenti
  for service in elasticsearch kibana logstash wazuh; do
    if docker ps -a --format '{{.Names}}' | grep -q "^${service}$"; then
      echo "[INFO] Rimozione forzata del container ${service}"
      docker rm -f "${service}" 2>/dev/null || echo "[WARN] Impossibile rimuovere il container ${service}"
    fi
  done

  docker-compose up -d || rollback
}

# Aggiorna il file filebeat.yml: copia dal container, sostituisce la stringa degli host,
# inserisce la direttiva per disabilitare la verifica del certificato,
# reinvia il file, riavvia il container e cancella il file locale
update_filebeat_config() {
  log_step "Copio il file filebeat.yml dal container wazuh all'host e aggiorno la configurazione"
  
  # Copia il file filebeat.yml dal container all'host
  docker cp wazuh:/etc/filebeat/filebeat.yml ./filebeat.yml || { echo "[ERROR] Impossibile copiare filebeat.yml dal container wazuh"; exit 1; }
  

  sed -i 's|^.*ssl.verification_mode:.*$|  ssl.verification_mode: none|g' ./filebeat.yml || { echo "[ERROR] Impossibile modificare ssl.verification_mode in filebeat.yml"; exit 1; }
  sed -i "s|^.*username:.*$|  username: 'elastic'|g" ./filebeat.yml || { echo "[ERROR] Impossibile modificare username in filebeat.yml"; exit 1; }
  sed -i "s|^.*password:.*$|  password: 'elastic'|g" ./filebeat.yml || { echo "[ERROR] Impossibile modificare password in filebeat.yml"; exit 1; }
  sed -i 's|^.*hosts:.*$|  hosts: ["https://elasticsearch:9200"]|g' ./filebeat.yml || { echo "[ERROR] Impossibile modificare hosts in filebeat.yml"; exit 1; }
  
  log_step "filebeat.yml aggiornato nella directory corrente."
  docker cp ./filebeat.yml wazuh:/etc/filebeat/filebeat.yml || { echo "[ERROR] Impossibile copiare filebeat.yml modificato nel container wazuh"; exit 1; }
  
  log_step "filebeat.yml aggiornato reinviato nel container wazuh."
  
  docker restart wazuh || { echo "[ERROR] Impossibile riavviare il container wazuh"; exit 1; }
  log_step "Container wazuh riavviato con la nuova configurazione."
  rm -f ./filebeat.yml
  log_step "File filebeat.yml rimosso dal host."
}


# Funzione principale che gestisce l'intero flusso
main() {
  check_prerequisites
  check_logstash_conf
  
  log_step "Avvio procedura di setup"

  # 1. Genera il file docker-compose iniziale (senza SSL) ed avvia i container
  generate_docker_compose_no_ssl || rollback
  log_step "Avvio dei container Docker (modalità senza SSL)"
  docker-compose up -d || rollback

  # 2. Genera i certificati SSL (e regola i permessi)
  log_step "Generazione dei certificati SSL"
  generate_certificates || rollback

  # 3. Aggiorna la configurazione abilitando SSL
  generate_docker_compose_with_ssl || rollback

  # 4. Riavvia i container per applicare la configurazione SSL
  restart_with_ssl || rollback
  
  # 5. Copia, aggiorna, reinvia il file filebeat.yml e riavvia il container wazuh
  update_filebeat_config || rollback

  log_step "Setup completato con successo!"
}

main "$@"
