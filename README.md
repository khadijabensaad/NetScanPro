# NetScan Pro 

**NetScan Pro** est un outil de supervision et découverte réseau basé sur le 
protocole **SNMP*. 
Il permet de scanner un sous-réseau, d'identifier les équipements actifs et 
d'en extraire des informations détaillées via une interface web interactive.

##  Fonctionnalités

-  **Scan de sous-réseau** : détection des hôtes actifs par ping et requêtes SNMP.
-  **Interrogation SNMP** : récupération des OIDs standards (sysDescr, 
  sysUpTime, sysContact, sysName, sysLocation, ifNumber).
-  **Détection automatique du type d'équipement** : routeur, switch, 
  serveur, imprimante, pare-feu, poste de travail.
-  **Historique des scans** : sauvegarde en base SQLite (sous-réseau, 
  communauté, équipements découverts).
-  **Export des résultats** : génération de rapports CSV et PDF.
-  **Interface web interactive** : tableau de bord avec visualisations 
  (Plotly) via Streamlit.
-  **Tests unitaires** inclus (pytest).

##  Stack technique

| Composant | Technologie |
|---|---|
| Interface web | Streamlit |
| Visualisation | Plotly, Pandas |
| Protocole réseau | SNMP (pysnmp), ping (ping3) |
| Base de données | SQLite |
| Génération PDF | ReportLab |
| Tests | Pytest |

##  Structure du projet
