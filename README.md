# CodeTwo Backup PST Forensic Tool

**Rootsektor IT-Security GmbH** | [www.rootsektor.de](https://www.rootsektor.de)

**Author:** Sebastian Michel (s.michel@rootsektor.de)

**Purpose:** Forensic PST Reconstruction from Encrypted CodeTwo Backups

---

## Verzeichnisstruktur

```
codetwo_pst_forensic/
├── main.py                  # CLI Einstiegspunkt
├── requirements.txt         # Python Abhängigkeiten
├── classes/                 # Alle Kernmodule
│   ├── banner.py            # Rootsektor ASCII-Banner
│   ├── config.py            # Konfiguration & MAPI-Konstanten
│   ├── crypto.py            # AES-256-CBC Entschlüsselung
│   ├── database.py          # SDF-Datenbank & Mailbox-XML Leser
│   ├── dll_loader.py        # .NET DLL Management (pythonnet)
│   ├── forensic_logger.py   # CSV/JSON Forensik-Logging
│   ├── processor.py         # Multiprocessing Batch-Verarbeitung
│   └── pst_builder.py       # PST-Erstellung mit Aspose.Email
└── dll/                     # Alle DLLs aus CodeTwo Backup
    ├── Aspose.Email.dll     # PST-Erstellung
    ├── C2.Ews.Client.*.dll  # FTS Stream Parser
    └── System.Data.SqlServerCe.dll
```

---

## Features

- Direkte Decrypt-to-PST Pipeline
- Multiprocessing für parallele Entschlüsselung
- Vollständiges Forensik-Logging (SHA256, Zeitstempel)
- Einzel- und Batch-Verarbeitung
- Fortschrittsanzeige mit ETA
- Nachrichten-Deduplizierung

---

## Installation

```bash
pip install -r requirements.txt
```

oder manuell:

```bash
pip install pythonnet pycryptodome rich
```

**Voraussetzungen:** Python 3.11+

---

## Verwendung

```bash
# Einzelne Mailbox verarbeiten
python main.py data/mailbox_folder -o output/

# Alle Mailboxen im Batch verarbeiten
python main.py data/ -o output/ --batch

# Mit mehreren Workern für schnellere Verarbeitung
python main.py data/ -o output/ --batch -w 8

# Verbose-Modus für detaillierte Ausgabe
python main.py data/ -o output/ --batch -v

# Quiet-Modus (nur Fehler)
python main.py data/ -o output/ --batch -q
```

---

## Ausgabe

Nach der Verarbeitung werden folgende Dateien erstellt:

| Datei | Beschreibung |
|-------|--------------|
| `<email>.pst` | Rekonstruierte PST-Datei |
| `<email>.forensic.csv` | Detailliertes Forensik-Log (pro Nachricht) |
| `<email>.forensic.json` | Zusammenfassung mit Statistiken |

---

## Forensik-Log Felder

| Feld | Beschreibung |
|------|--------------|
| `timestamp` | Verarbeitungszeitpunkt |
| `source_file` | Originale .dac Datei |
| `source_hash_sha256` | SHA256 Hash der verschlüsselten Datei |
| `encrypted_size` | Größe verschlüsselt (Bytes) |
| `decrypted_size` | Größe entschlüsselt (Bytes) |
| `folder_id` / `folder_name` | Zielordner in der PST |
| `subject` / `sender` | E-Mail Metadaten |
| `message_date` | Nachrichtendatum |
| `is_read` | Gelesen-Status |
| `attachment_count` | Anzahl Anhänge |
| `status` | SUCCESS / DUPLICATE / ERROR |
