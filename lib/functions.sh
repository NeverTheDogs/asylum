#!/bin/bash

#FUNZIONI DI LOG
log_info() {echo -e "${CYAN}[INFO]${NC} $1"}
log_success() {echo -e "${GREEN}[SUCCESS]${NC} $1"}
log_warning() {echo -e "${YELLOW}[WARNING]${NC} $1"}
log_error() {echo -e "${RED}[ERROR]${NC} $1"}

# FUNZIONE: Verifica privilegi di root
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
      log_error "Questo script deve essere eseguito come root."
      exit 1
  fi
}

configure_certificates() {
  log_info "Download di wazuh-certs-tool.sh e config.yml..."
  curl -sO "${WAZUH_CERT_TOOL}" || { log_error "Download fallito."; exit 1; }
  curl -sO "${WAZUH_CERT_CONFIG}" || { log_error "Download fallito."; exit 1; }
  
  log_info "Sostituzione dei placeholder con l'IP di questo nodo (${WAZUH_SERVER_IP})..."
  sed -i "s|<indexer-node-ip>|${WAZUH_SERVER_IP}|g" config.yml
  sed -i "s|<wazuh-manager-ip>|${WAZUH_SERVER_IP}|g" config.yml
  sed -i "s|<dashboard-node-ip>|${WAZUH_SERVER_IP}|g" config.yml

  log_info "Esecuzione del tool per generare i certificati..."
  bash ./wazuh-certs-tool.sh -A
  if [ $? -ne 0 ]; then
    log_error "wazuh-certs-tool.sh ha restituito un errore."
    exit 1
  fi
  log_success "Certificati generati correttamente..."
  log_info "Compressione dei certificati..."
  if [ -d "./wazuh-certificates" ]; then
    tar -czvf "${CERT_ARCHIVE}" -C ./wazuh-certificates .
    log_success "Archivio dei certificati creato in: ${CERT_ARCHIVE}"
    log_info "Pulizia file residui..."
    rm -f wazuh-certificates-tool.log  wazuh-certs-tool.sh config.yml
  else
    log_error "Directory './wazuh-certificates' non trovata. Genera prima i certificati."
    exit 1
  fi
}

# Deploy certificati nell'Indexer single-node
deploy_indexer_certificates() {

  log_info "Deploy dei certificati in /etc/wazuh-indexer/certs"
  mkdir -p /etc/wazuh-indexer/certs

  # Estrai i certificati specifici per il nodo
  tar -xzf "${CERT_ARCHIVE}" -C /etc/wazuh-indexer/certs "./${NODE_NAME}.pem" "./${NODE_NAME}-key.pem" "./root-ca.pem" "./admin.pem" "./admin-key.pem"

  # Rinomina secondo le attese di OpenSearchSecurityPlugin
  if [ -f /etc/wazuh-indexer/certs/${NODE_NAME}.pem ]; then
    mv "/etc/wazuh-indexer/certs/${NODE_NAME}.pem" "/etc/wazuh-indexer/certs/indexer.pem"
  fi
  if [ -f /etc/wazuh-indexer/certs/${NODE_NAME}-key.pem ]; then
    mv "/etc/wazuh-indexer/certs/${NODE_NAME}-key.pem" "/etc/wazuh-indexer/certs/indexer-key.pem"
  fi

  # Imposta permessi e proprietario
  chmod 640 /etc/wazuh-indexer/certs/*
  chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
  log_success "Certificati deployati correttamente in /etc/wazuh-indexer/certs."

  #Avvia l'Indexer per far caricare i certificati
  log_info "Avvio iniziale di wazuh-indexer per applicare i certificati..."
  systemctl daemon-reload
  systemctl enable wazuh-indexer
  systemctl start wazuh-indexer

  # Verifica la presenza della directory securityconfig
  log_info "Verifica della directory securityconfig..."
  if [ ! -d /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig ]; then
    mkdir -p /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig
    log_info "Creata la directory securityconfig."
  fi

  # Scarica i file di configurazione di OpenSearch Security
  log_info "Scaricamento file di configurazione per OpenSearch Security..."
  cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig
  curl -sO "https://raw.githubusercontent.com/opensearch-project/security/2.x/config/config.yml"
  curl -sO "https://raw.githubusercontent.com/opensearch-project/security/2.x/config/roles.yml"
  curl -sO "https://raw.githubusercontent.com/opensearch-project/security/2.x/config/roles_mapping.yml"
  curl -sO "https://raw.githubusercontent.com/opensearch-project/security/2.x/config/internal_users.yml"
  curl -sO "https://raw.githubusercontent.com/opensearch-project/security/2.x/config/action_groups.yml"
  curl -sO "https://raw.githubusercontent.com/opensearch-project/security/2.x/config/tenants.yml"
  curl -sO "https://raw.githubusercontent.com/opensearch-project/security/2.x/config/nodes_dn.yml"
  curl -sO "https://raw.githubusercontent.com/opensearch-project/security/2.x/config/whitelist.yml"

  # Imposta permessi e proprietario sui file di configurazione
  log_info "Impostazione permessi per i file di configurazione..."
  chown -R wazuh-indexer:wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig
  chmod 640 /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/*

  # Inizializza OpenSearch Security
  log_info "Inizializzazione di OpenSearch Security..."
  /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
    -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/ \
    -icl -key /etc/wazuh-indexer/certs/admin-key.pem \
    -cert /etc/wazuh-indexer/certs/admin.pem \
    -cacert /etc/wazuh-indexer/certs/root-ca.pem \
    -nhnv

  if [ $? -eq 0 ]; then
    log_success "OpenSearch Security inizializzato correttamente."
  else
    log_error "Errore durante l'inizializzazione di OpenSearch Security."
    exit 1
  fi
}

install_server() {
  log_info "Installazione di Wazuh Manager..."
  apt-get install -y wazuh-manager

  log_info "Download e installazione di Filebeat..."
  curl -sO "https://packages.wazuh.com/4.x/apt/pool/main/f/filebeat/${FILEBEAT_DEB}"
  dpkg -i ./"${FILEBEAT_DEB}"

  log_info "Configurazione di Filebeat..."
  curl -so "/etc/filebeat/filebeat.yml" "https://packages.wazuh.com/4.11/tpl/wazuh/filebeat/filebeat.yml"
  # Modificare il file di configurazione per configurare l'indirizzo dell'Indexer
  sed -i 's/hosts: \["127.0.0.1:9200"\]/hosts: \["'"${WAZUH_SERVER_IP}"':9200"\]/' /etc/filebeat/filebeat.yml

  # Creare un keystore per le credenziali
  log_info "Configurazione credenziali Filebeat..."
  rm -f /var/lib/filebeat/filebeat.keystore
  filebeat keystore create --force
  echo "${WAZUH_USER}" | filebeat keystore add username --stdin --force
  echo "${WAZUH_PASS}" | filebeat keystore add password --stdin --force

  log_info "Configurazione integrazione modulo Wazuh..."
  curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.11.2/extensions/elasticsearch/7.x/wazuh-template.json
  chmod 644 /etc/filebeat/wazuh-template.json
  curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | tar -xvz -C /usr/share/filebeat/module

  log_info "Deploy dei certificati in /etc/filebeat/certs..."
  mkdir -p /etc/filebeat/certs
  tar -xzf ${CERT_ARCHIVE} -C /etc/filebeat/certs "./${NODE_NAME}.pem" "./${NODE_NAME}-key.pem" "./root-ca.pem"

  # Rinomina secondo le attese per Filebeat
  if [ -f "/etc/filebeat/certs/${NODE_NAME}.pem" ]; then
    mv "/etc/filebeat/certs/${NODE_NAME}.pem" "/etc/filebeat/certs/filebeat.pem"
  fi
  if [ -f "/etc/filebeat/certs/${NODE_NAME}-key.pem" ]; then
    mv "/etc/filebeat/certs/${NODE_NAME}-key.pem" "/etc/filebeat/certs/filebeat-key.pem"
  fi

  chmod 640 /etc/filebeat/certs/*
  chown -R root:root /etc/filebeat/certs
  log_success "Certificati deployati correttamente in /etc/filebeat/certs."

  log_info "Configurazione della connessione con l'Indexer nel Wazuh Manager..."
  # Salvare le credenziali dell'Indexer nel keystore del Manager
  echo "${WAZUH_USER}" | /var/ossec/bin/wazuh-keystore -f indexer -k username
  echo "${WAZUH_PASS}" | /var/ossec/bin/wazuh-keystore -f indexer -k password

  # Modificare ossec.conf per configurare la connessione con l'Indexer
  sed -i 's|<host>https://0.0.0.0:9200</host>|<host>https://'${WAZUH_SERVER_IP}':9200</host>|' /var/ossec/etc/ossec.conf

  log_info "Avvio dei servizi Wazuh Manager e Filebeat..."
  systemctl daemon-reload
  systemctl enable wazuh-manager
  systemctl restart wazuh-manager
  systemctl enable filebeat
  systemctl restart filebeat

  # Verifica dello stato
  filebeat test config
  filebeat test output
  log_success "Wazuh Manager e Filebeat installati e configurati correttamente."
}

# FUNZIONE: Installazione Dashboard
install_dashboard(){
  apt-get -y install wazuh-dashboard
  log_info "Deploy dei certificati in /etc/wazuh-dashboard/certs"
  mkdir -p /etc/wazuh-dashboard/certs

  # Estrai i certificati specifici per il nodo
  tar -xzf "${CERT_ARCHIVE}" -C "/etc/wazuh-dashboard/certs" "./${NODE_NAME}.pem" "./${NODE_NAME}-key.pem" "./root-ca.pem"

  # Rinomina secondo le attese per il Dashboard
  if [ -f /etc/wazuh-dashboard/certs/${NODE_NAME}.pem ]; then
    mv /etc/wazuh-dashboard/certs/${NODE_NAME}.pem /etc/wazuh-dashboard/certs/dashboard.pem
  fi
  if [ -f /etc/wazuh-dashboard/certs/${NODE_NAME}-key.pem ]; then
    mv /etc/wazuh-dashboard/certs/${NODE_NAME}-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
  fi

  # Imposta permessi e proprietario
  chmod 640 /etc/wazuh-dashboard/certs/*
  chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
  log_success "Certificati deployati correttamente in /etc/wazuh-dashboard/certs."

  systemctl daemon-reload
  systemctl enable wazuh-dashboard
  systemctl restart wazuh-dashboard
  #sed -i "s|<localhost>|${WAZUH_SERVER_IP}|g" /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
  #systemctl restart wazuh-dashboard
}

install_Jira(){
  log_info "Installazione di OpenJDK e PostgreSQL..."
  apt install -y openjdk-11-jdk postgresql postgresql-contrib

  postgres psql <<EOF
CREATE USER jirauser WITH PASSWORD 'jirauser';
CREATE DATABASE jiradb WITH OWNER jirauser ENCODING 'UTF8';
GRANT ALL PRIVILEGES ON DATABASE jiradb TO jirauser;
EOF

  sed -i 's/^\(local\s\+all\s\+all\s\+\)peer/\1md5/' /etc/postgresql/12/main/pg_hba.conf
  systemctl restart postgresql
  log_success "OpenJDK e PostgreSQL installato con successo."

  log_info "Installazione di Jira..."
  wget https://www.atlassian.com/software/jira/downloads/binary/atlassian-jira-core-8.21.1-x64.bin
  chmod a+x atlassian-jira-core-8.21.1-x64.bin
  ./atlassian-jira-core-8.21.1-x64.bin

  log_success "Jira installato con successo..."
}


# FUNZIONE: Installazione completa dei componenti
installEverything() {

  log_info "Aggiunta della chiave GPG di Wazuh..."
  curl -fsSL "${GPG_KEY_URL}" | gpg --no-default-keyring --keyring /usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

  log_info "Aggiunta del repository Wazuh..."
  cat <<EOF >/etc/apt/sources.list.d/wazuh.list
deb [signed-by=/usr/share/keyrings/wazuh.gpg] ${WAZUH_REPO_URL} stable main
EOF
  
  log_info "Aggiunta del repository PHP..."
  wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
  echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/php.list

  #Generazione certificati
  log_info "Download e generazione dei certificati SSL..."
  configure_certificates

  #Installazione dell'Indexer
  log_info "Installazione di Wazuh Indexer..."
  apt-get install -y wazuh-indexer

  #Deploy dei certificati
  log_info "Deploy dei certificati in wazuh-indexer..."
  deploy_indexer_certificates

  # Installa il server Wazuh (Server + Filebeat)
  log_info "Installazione Wazuh Server & Filebeat"
  install_server

  log_info "Installazione Dashboard..."
  install_dashboard
  log_success "Installazione completa del nodo singolo Wazuh completata!"

  log_info "Installazione Jira"
  install_Jira
}


# FUNZIONE: Rimozione dei componenti
removeEverything() {
  rm -rf /var/log/wazuh-indexer /var/lib/wazuh-indexer /etc/wazuh-indexer wazuh-certificates /usr/share/wazuh-indexer /etc/filebeat /usr/share/filebeat
  
  if [ "${FILEBEAT_DEB:-}" != "" ]; then
    if [ -e "./${FILEBEAT_DEB}" ]; then
      rm -f "./${FILEBEAT_DEB}" && log_info "Rimosso: ./${FILEBEAT_DEB}" || log_warning "Impossibile rimuovere: ./${FILEBEAT_DEB}"
    else
      log_info "Il file ./${FILEBEAT_DEB} non esiste, salto."
    fi
  else
    log_info "La variabile FILEBEAT_DEB non è definita. Salto la rimozione del relativo file."
  fi
   if [ -e "wazuh-certificates-tool.log" ]; then
    rm -f wazuh-certificates-tool.log && log_info "Rimosso: wazuh-certificates-tool.log" || log_warning "Impossibile rimuovere: wazuh-certificates-tool.log"
  else
    log_info "Il file wazuh-certificates-tool.log non esiste, salto."
  fi

  if [ -e "wazuh-certs-tool.sh" ]; then
    rm -f wazuh-certs-tool.sh && log_info "Rimosso: wazuh-certs-tool.sh" || log_warning "Impossibile rimuovere: wazuh-certs-tool.sh"
  else
    log_info "Il file wazuh-certs-tool.sh non esiste, salto."
  fi

  if [ -e "config.yml" ]; then
    rm -f config.yml && log_info "Rimosso: config.yml" || log_warning "Impossibile rimuovere: config.yml"
  else
    log_info "Il file config.yml non esiste, salto."
  fi

  log_info "Arresto dei servizi Wazuh..."
  systemctl stop wazuh-manager || true
  systemctl stop wazuh-indexer || true
  systemctl stop filebeat || true
  systemctl stop wazuh-dashboard || true
  #systemctl stop apache2 || true

  log_info "Disabilitazione dei servizi Wazuh..."
  systemctl disable wazuh-manager || true
  systemctl disable wazuh-indexer || true
  systemctl disable filebeat || true
  systemctl disable wazuh-dashboard || true
  #systemctl disable apache2 || true

  log_info "Rimozione dei pacchetti Wazuh (Manager, Indexer, Filebeat, Dashboard)..."
  apt-get purge -y wazuh-manager wazuh-indexer wazuh-dashboard filebeat #postgresql

  log_info "Rimozione del repository Wazuh..."
  rm -f /etc/apt/sources.list.d/wazuh.list

  log_info "Rimozione della chiave GPG di Wazuh..."
  if [ -f /usr/share/keyrings/wazuh.gpg ]; then
      rm -f /usr/share/keyrings/wazuh.gpg
      log_success "Chiave GPG rimossa con successo."
  else
      log_warning "Nessuna chiave GPG di Wazuh trovata."
  fi

  log_info "Rimozione del repository PHP..."
  rm -f /etc/apt/sources.list.d/php.list

  log_info "Rimozione della chiave GPG di PHP..."
  if [ -f /etc/apt/trusted.gpg.d/php.gpg ]; then
      rm -f /etc/apt/trusted.gpg.d/php.gpg
      log_success "Chiave GPG di PHP rimossa con successo."
  else
      log_warning "Nessuna chiave GPG di PHP trovata."
  fi

  log_info "Pulizia dei pacchetti inutilizzati..."
  apt-get autoremove -y
  apt-get update

  log_success "Rimozione completata con successo!"
}