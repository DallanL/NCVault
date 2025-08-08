# NCVault
program to interact with a NetSapiens VoIP API to locally store a domain's: CDRs, call recordings, transcripts/sentiment analysis

## Installation

### Recommended (Windows)

**Download & run the latest Windows portable executable**  
   Grab the newest `.exe` from the “Latest release” page—this is the simplest way to get up and running on Window
   [Download NCVault Installer for Windows](https://github.com/DallanL/NCVault/releases/latest/)


### Alternate (From Source)

> If you’d rather work from the code directly—on Linux, macOS, or Windows, then you can clone and run with Python:

1. **Clone the repository**  
```bash
git clone https://github.com/DallanL/NCVault.git
cd NCVault
```
   
2. **Create & activate a virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate   # macOS/Linux  
venv\Scripts\activate      # Windows PowerShell
```

3. **Install dependencies**   
```bash
pip install -r requirements.txt
```

4. **Run NCVault**
```bash
python3 -m ncvault --help
```

## RoadMap
[x] - Replace plaintext API key storage with keyring; migrate existing configs and delete the key from disk. 

[ ] - Introduce a local SQLite catalog (with FTS5) and asset checksums; backfill existing files. 

[ ] - Add tenacity-based retries + .part atomic writes + SHA-256 verification. 

[ ] - Harden logging (PII scrub + rotation) per OWASP guidance. 

[ ] - Sanitize filenames for Windows reserved chars and cap path length; document long-path behavior. 

[ ] - Package with PyInstaller and sign the binary; publish a signed test build and validate on a clean Windows 11 box. 

[ ] - Add retention settings + “Secure Purge” and document CPNI/CPRA posture in the README

[ ] - Add UI elements to browse/search the saved call history files

[ ] - Add downloading of voicemails: metadata, audio file, transcription

[ ] - Add downloading of sms/mms messages
