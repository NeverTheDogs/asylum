#!/usr/bin/env python3
import requests
import json
from requests.auth import HTTPBasicAuth

# Disabilita i warning sui certificati HTTPS (solo per test; in produzione verifica sempre i certificati)
requests.packages.urllib3.disable_warnings()

# -----------------------------
# CONFIGURAZIONE WAZUH
# -----------------------------
wazuh_base_url   = "https://localhost:55000"
wazuh_username   = "wazuh-wui"
wazuh_password   = "wazuh-wui"
wazuh_auth_endpoint = f"{wazuh_base_url}/security/user/authenticate"

auth_response = requests.get(
    wazuh_auth_endpoint,
    auth=(wazuh_username, wazuh_password),
    headers={"Content-Type": "application/json"},
    verify=False
)
if auth_response.status_code != 200:
    print("Errore nell'autenticazione a Wazuh:")
    print(auth_response.text)
    exit(1)
wazuh_token = auth_response.json()["data"]["token"]
print("Token Wazuh ottenuto correttamente.")

wazuh_headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {wazuh_token}"
}

agents_endpoint = f"{wazuh_base_url}/agents"
agents_response = requests.get(agents_endpoint, headers=wazuh_headers, verify=False)
if agents_response.status_code != 200:
    print("Errore nella richiesta dei dati degli agenti da Wazuh:")
    print(agents_response.text)
    exit(1)

wazuh_data = agents_response.json()
agent_groups = {}
if "data" in wazuh_data and "affected_items" in wazuh_data["data"]:
    for agent in wazuh_data["data"]["affected_items"]:
        agent_id = agent.get("id")
        group = agent.get("group", "Unknown")
        agent_groups[agent_id] = group
else:
    print("Nessun dato agente trovato in Wazuh!")
    exit(1)
print("Mapping dei gruppi degli agenti ottenuto da Wazuh:", agent_groups)

# -----------------------------
# CONFIGURAZIONE ELASTICSEARCH (solo Critical, test con numeri piccoli)
# -----------------------------
es_url      = "https://localhost:9200/wazuh-states-vulnerabilities-cocoqri/_search?scroll=1m"
es_auth     = ("admin", "admin")
es_headers  = {"Content-Type": "application/json"}

es_query = {
    "query": {
        "match": {
            "vulnerability.severity": "Critical"
        }
    },
    "_source": [
        "agent.id", 
        "agent.name",
        "vulnerability.reference",
        "vulnerability.severity",
        "vulnerability.detected_at",
        "vulnerability.score",
        "vulnerability.description",
        "vulnerability.id",
        "vulnerability.category",
        "vulnerability.published_at"
    ],
    "size": 10
}

all_hits = []
print("Inizio estrazione dati da Elasticsearch tramite Scroll API (solo Critical)...")
es_response = requests.get(es_url, auth=es_auth, headers=es_headers, json=es_query, verify=False)
if es_response.status_code != 200:
    print("Errore nella query Elasticsearch:")
    print(es_response.text)
    exit(1)
es_data = es_response.json()
all_hits.extend(es_data.get("hits", {}).get("hits", []))
scroll_id = es_data.get("_scroll_id")

while True:
    scroll_payload = {"scroll": "1m", "scroll_id": scroll_id}
    scroll_url   = "https://localhost:9200/_search/scroll"
    scroll_response = requests.get(scroll_url, auth=es_auth, headers=es_headers, json=scroll_payload, verify=False)
    scroll_data     = scroll_response.json()
    hits = scroll_data.get("hits", {}).get("hits", [])
    if not hits:
        break
    all_hits.extend(hits)
    scroll_id = scroll_data.get("_scroll_id")
print(f"Estrazione completata: {len(all_hits)} documenti estratti.")

for hit in all_hits:
    source = hit.get("_source", {})
    agent_info = source.get("agent", {})
    agent_id = agent_info.get("id")
    agent_info["group"] = agent_groups.get(agent_id, "Unknown")
    
    vuln = source.get("vulnerability", {})
    if vuln:
        new_vuln = {
            "reference": vuln.get("reference"),
            "severity": vuln.get("severity"),
            "detected": vuln.get("detected_at"),
            "score": vuln.get("score", {}).get("base") if isinstance(vuln.get("score"), dict) else vuln.get("score"),
            "description": vuln.get("description"),
            "id": vuln.get("id"),
            "category": vuln.get("category"),
            "published": vuln.get("published_at")
        }
        source["vulnerability"] = new_vuln

# -----------------------------
# CONFIGURAZIONE JIRA
# -----------------------------
jira_base_url     = "http://192.168.1.103:8080"
jira_api_endpoint = f"{jira_base_url}/rest/api/2/issue"
jira_username     = "jirauser"
jira_password     = "jirauser"
jira_project_key  = "AS"
jira_issue_type   = "Task"
jira_headers = {
    "Content-Type": "application/json",
    "Accept": "application/json"
}

security_mapping = {
    "winadmins": "10003",
    "unixadmins": "10002"
}
default_security_id = "10002"

# Impostiamo dei default per eventuali fallback ma qui preferiamo recuperare dinamicamente le transizioni
default_non_risolti_id = 51   # Ex "Riapri" (da usare se necessario)
default_resolved_id     = 32   # Ex "Resolved" (se necessario)

def get_security_level(group):
    if isinstance(group, list):
        for g in group:
            key = g.lower().strip()
            if key in security_mapping:
                return security_mapping[key]
        return default_security_id
    else:
        return security_mapping.get(group.lower().strip(), default_security_id)

def normalize_group(group):
    if isinstance(group, list):
        return ", ".join(sorted(g.strip() for g in group))
    return group.strip()

def get_existing_issues():
    jql = 'project = "{}" AND issuetype = Task AND labels = imported_vulnerability'.format(jira_project_key)
    search_url = f"{jira_base_url}/rest/api/2/search"
    params = {"jql": jql, "fields": "summary"}
    response = requests.get(
        search_url,
        auth=HTTPBasicAuth(jira_username, jira_password),
        headers=jira_headers,
        params=params
    )
    existing = {}
    if response.status_code == 200:
        issues = response.json().get("issues", [])
        for issue in issues:
            issue_key = issue.get("key")
            summary = issue.get("fields", {}).get("summary", "")
            existing[summary] = issue_key
    else:
        print("Errore nel recuperare le issue esistenti:", response.text)
    return existing

def create_jira_issue(summary, description, security_level_id):
    payload = {
        "fields": {
            "project": {"key": jira_project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": jira_issue_type},
            "security": {"id": security_level_id},
            "labels": ["imported_vulnerability"]
        }
    }
    response = requests.post(
        jira_api_endpoint,
        auth=HTTPBasicAuth(jira_username, jira_password),
        headers=jira_headers,
        json=payload
    )
    return response

def update_jira_issue(issue_key, summary, description):
    payload = {
        "fields": {
            "summary": summary,
            "description": description
        }
    }
    update_url = f"{jira_api_endpoint}/{issue_key}"
    response = requests.put(
        update_url,
        auth=HTTPBasicAuth(jira_username, jira_password),
        headers=jira_headers,
        json=payload
    )
    return response

def transition_issue_to_non_risolti(issue_key, transition_id):
    payload = {"transition": {"id": transition_id}}
    transition_url = f"{jira_api_endpoint}/{issue_key}/transitions"
    response = requests.post(
        transition_url,
        auth=HTTPBasicAuth(jira_username, jira_password),
        headers=jira_headers,
        json=payload
    )
    return response

def get_available_transitions(issue_key):
    url = f"{jira_api_endpoint}/{issue_key}/transitions?expand=transitions.fields"
    response = requests.get(url, auth=HTTPBasicAuth(jira_username, jira_password), headers=jira_headers)
    if response.status_code == 200:
        return response.json().get("transitions", [])
    else:
        print(f"Errore nel recuperare le transizioni per {issue_key}: {response.text}")
        return []

def add_comment(issue_key, comment):
    """
    Aggiunge un commento all'issue specificata.
    """
    url = f"{jira_base_url}/rest/api/2/issue/{issue_key}/comment"
    payload = {"body": comment}
    response = requests.post(url, auth=HTTPBasicAuth(jira_username, jira_password), headers=jira_headers, json=payload)
    return response

# -----------------------------
# PROCESSO DI CREAZIONE/AGGIORNAMENTO DELLE ISSUE IN JIRA
# -----------------------------
# Filtra i duplicati: per ogni summary univoco conserva solo il primo hit
unique_hits = {}
for hit in all_hits:
    source = hit.get("_source", {})
    agent = source.get("agent", {})
    vuln  = source.get("vulnerability", {})
    if not vuln:
        continue
    group_raw = agent.get("group", "Unknown")
    group_normalized = normalize_group(group_raw)
    summary = (
        f"{agent.get('id', 'N/D')} - {group_normalized} - "
        f"[{agent.get('name', 'N/D')}] - {vuln.get('severity', 'N/D')} - [{vuln.get('id', 'N/D')}]"
    )
    if summary not in unique_hits:
        unique_hits[summary] = hit

existing_issues = get_existing_issues()  # Dizionario: chiave = summary, valore = issue key
current_summaries = set()

print("Inizio processo di creazione/aggiornamento delle issue in Jira (solo Critical):")
for summary, hit in unique_hits.items():
    current_summaries.add(summary)
    source = hit.get("_source", {})
    agent = source.get("agent", {})
    vuln  = source.get("vulnerability", {})
    
    description = (
        f"*Dettagli Vulnerabilità:*\n"
        f"- **ID:** {vuln.get('id', 'N/D')}\n"
        f"- **Reference:** {vuln.get('reference', 'N/D')}\n"
        f"- **Severity:** {vuln.get('severity', 'N/D')}\n"
        f"- **Detected At:** {vuln.get('detected', 'N/D')}\n"
        f"- **Score:** {vuln.get('score', 'N/D')}\n"
        f"- **Category:** {vuln.get('category', 'N/D')}\n"
        f"- **Published At:** {vuln.get('published', 'N/D')}\n\n"
        f"*Descrizione:*\n{vuln.get('description', 'Nessuna descrizione')}\n"
    )
    
    security_level_id = get_security_level(normalize_group(agent.get("group", "Unknown")))
    
    if summary in existing_issues:
        issue_key = existing_issues[summary]
        issue_get_url = f"{jira_api_endpoint}/{issue_key}?fields=description,resolution"
        issue_get_response = requests.get(
            issue_get_url,
            auth=HTTPBasicAuth(jira_username, jira_password),
            headers=jira_headers
        )
        if issue_get_response.status_code == 200:
            current_issue = issue_get_response.json()
            current_description = current_issue["fields"].get("description", "")
            current_resolution = current_issue["fields"].get("resolution", None)
            current_resolution_name = current_resolution["name"] if current_resolution else None

            # Se la descrizione è cambiata oppure l'issue risulta chiusa (es. "completato")
            if current_description != description or (current_resolution and current_resolution["name"].lower() in ["completato", "fatto", "resolved"]):
                if not (current_resolution and current_resolution["name"].lower() == "non risolti"):
                    transitions = get_available_transitions(issue_key)
                    desired_transition = None
                    for t in transitions:
                        if t["name"].lower() in ["riapri", "riapri e avvia procedura"]:
                            desired_transition = t
                            break
                    if desired_transition:
                        transition_id = int(desired_transition["id"])
                        trans_response = transition_issue_to_non_risolti(issue_key, transition_id)
                        if trans_response.status_code in [200, 204]:
                            print(f"Issue {issue_key} transizionata a 'Non Risolti' per: {summary}")
                            comment_response = add_comment(issue_key, "Riaperto da sistema. Vulnerabilità ancora rilevata.")
                            if comment_response.status_code not in [200, 201]:
                                print(f"Errore nell'aggiungere commento su {issue_key}: {comment_response.text}")
                        else:
                            print(f"Errore nella transizione dell'issue {issue_key} per {summary}: {trans_response.text}")
                    else:
                        print(f"Nessuna transizione valida trovata per l'issue {issue_key} con summary {summary}")
                else:
                    print(f"Issue {issue_key} è già in stato 'Non Risolti' per {summary} (ma potrebbe essere cambiato il contenuto)")
            else:
                print(f"Nessuna modifica rilevata per l'issue {issue_key} con summary {summary}.")
        else:
            print(f"Errore nel recuperare i dettagli dell'issue {issue_key}: {issue_get_response.text}")
    else:
        create_response = create_jira_issue(summary, description, security_level_id)
        if create_response.status_code in [200, 201]:
            data = create_response.json()
            new_issue_key = data.get("key")
            print(f"Issue creata: {summary} (Issue key: {new_issue_key})")
            existing_issues[summary] = new_issue_key
        else:
            print(f"Errore nella creazione dell'issue per {summary}: {create_response.text}")

# -----------------------------
# TRANSIZIONE DELLE ISSUE NON PIÙ PRESENTI A "Resolved"
# -----------------------------
print("Avvio processo di transizione delle issue non più rilevate a 'Resolved':")
for summary, issue_key in existing_issues.items():
    if summary not in current_summaries:
        transitions = get_available_transitions(issue_key)
        resolved_transition = None
        for t in transitions:
            if t["name"].lower() in ["completato", "fatto", "resolved"]:
                resolved_transition = t
                break

        if resolved_transition:
            transition_id = int(resolved_transition["id"])
            trans_response = transition_issue_to_non_risolti(issue_key, transition_id)
            if trans_response.status_code in [200, 204]:
                print(f"Issue {issue_key} con summary '{summary}' è stata transizionata a '{resolved_transition['to']['name']}'.")
                # Aggiunge il commento di chiusura
                comment_response = add_comment(issue_key, "Chiuso in automatico dal sistema. Vulnerabilità non rilevata.")
                if comment_response.status_code not in [200, 201]:
                    print(f"Errore nell'aggiungere commento su {issue_key}: {comment_response.text}")
            else:
                print(f"Errore nella transizione dell'issue {issue_key}: {trans_response.text}")
        else:
            print(f"Nessuna transizione 'Resolved' disponibile per l'issue {issue_key} con summary '{summary}'.")
print("Processo completato.")