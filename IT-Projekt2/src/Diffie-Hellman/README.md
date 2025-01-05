# Diffie-Hellman Schlüsselaustausch mit REST API

Dieses Projekt implementiert einen sicheren Schlüsselaustausch mittels Diffie-Hellman-Algorithmus über eine REST-API. Es besteht aus einem Flask-Server und einem Python-Client, die den Schlüsselaustausch durchführen und anschließend Daten verschlüsselt übertragen.

## Funktionsweise

### 1. Grundlegendes Setup
- Der Server läuft auf Flask und bietet REST-Endpoints für die Kommunikation
- Der Client kommuniziert mit dem Server über HTTP-Requests
- Beide Seiten protokollieren Performance-Metriken in Log- und CSV-Dateien

### 2. Diffie-Hellman Prozess

#### a) Initialisierung (/init)
- Server generiert DH-Parameter (Primzahl p und Generator g)
- Parameter werden zum Client übertragen
- Sicherheitsstärke: 2048 Bit

#### b) Schlüsselaustausch (/exchange)
1. Client und Server generieren jeweils:
   - Private Schlüssel (a bzw. b)
   - Öffentliche Schlüssel (g^a mod p bzw. g^b mod p)
2. Öffentliche Schlüssel werden ausgetauscht
3. Beide Seiten berechnen den identischen Shared Secret:
   - Client: (g^b)^a mod p
   - Server: (g^a)^b mod p

#### c) Verschlüsselung und Übertragung (/decrypt)
1. Shared Secret wird zu AES-256 Schlüssel abgeleitet (HKDF)
2. Client:
   - Holt Daten von externer URL
   - Generiert zufälligen IV
   - Verschlüsselt Daten (AES-256-CBC)
   - Sendet IV und verschlüsselte Daten
3. Server:
   - Empfängt und entschlüsselt Daten
   - Protokolliert Zeitmessungen

### 3. Sicherheitsmerkmale
- Private Schlüssel bleiben geheim
- Nur öffentliche Parameter werden übertragen
- Verwendung von IVs für sichere Verschlüsselung
- PKCS7-Padding für korrekte Blocklängen

## Struktur

- `server.py`: Flask-Server mit DH-Implementation
- `client.py`: Client-Anwendung für DH-Austausch
- `server_output_dh.txt`: Server-Logdatei
- `client_output_dh.txt`: Client-Logdatei
- `server_timings_dh.csv`: Performance-Metriken des Servers
- `client_timings_dh.csv`: Performance-Metriken des Clients

## Installation

Benötigte Python-Pakete installieren:

```bash
pip install flask requests cryptography
```


## Verwendung

1. Server starten:

```bash
python server.py
```

2. Client in separatem Terminal starten:

```bash
python client.py
```


## Performance-Monitoring

Das System führt 1000 Iterationen durch und protokolliert:
- Schlüsselgenerierungszeit
- Shared-Secret-Berechnungszeit
- Ver-/Entschlüsselungszeit

Die Ergebnisse werden in CSV-Dateien gespeichert für spätere Analyse.

## Technische Details

- **Protokoll**: REST API über HTTP
- **Kryptographie**: 
  - Diffie-Hellman (2048 Bit)
  - AES-256-CBC
  - HKDF für Schlüsselableitung
  - PKCS7-Padding
- **Framework**: Flask
- **Sprache**: Python 3

## Sicherheitshinweise

Dieses System ist für Demonstrations- und Testzwecke gedacht. Für Produktivumgebungen sollten zusätzliche Sicherheitsmaßnahmen implementiert werden:
- TLS/SSL für die REST-API
- Authentifizierung
- Zusätzliche Integritätsprüfungen

## Anpassungen

- Server-IP und Port können in beiden Skripten angepasst werden
- Standardmäßig läuft der Server auf Port 4999
- Die URL für die zu verschlüsselnden Daten kann im Client angepasst werden