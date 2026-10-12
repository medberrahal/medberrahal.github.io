---
layout: single
header:
  overlay_image: /assets/images/banner-011.jpg
  overlay_filter: 0.6
# classes: wide

toc: true
toc_label: "Table of Contents"
# toc_icon: "cog"

last_modified_at: 2025-11-24T22:20:26-04:00

categories:
  - tutorial
tags:
  - elastic
  - evtx
  - ELK

---

🚀 **Project Overview**: This project demonstrates a robust pipeline for ingesting and analyzing forensically collected Windows Event Log files (`.evtx`) into the Elastic Stack (Elasticsearch, Kibana) using **Winlogbeat**. This process is critical in digital forensics and security operations for efficient threat hunting and evidence review.

The pipeline is automated using a PowerShell script to iterate through multiple EVTX files, ensuring each file is treated as a new source for proper ingestion and analysis.

### 🔑 Key Features

- **Forensic Ingestion Configuration:** Custom `winlogbeat-forensic.yml` is configured to handle offline EVTX files, setting `no_more_events: stop` and `start_at: oldest`.

- **Batch Automation:** A PowerShell script (`ingest.ps1`) automates the ingestion of all `.evtx` files found within a specified evidence directory.

- **Registry Nuking:** The batch script critically removes the local Winlogbeat registry data (`.\data`) before processing each file to force Winlogbeat to treat every EVTX file as a new log source.

- **Security Monitoring Setup:** Includes steps for installing **Sysmon** to generate enhanced endpoint telemetry for richer forensic data.

- **Cloud Integration:** Configuration uses Elastic Cloud ID and API key for secure data upload.


### 🛠️ Technologies Used

|**Category**|**Component**|**Description / Purpose**|
|---|---|---|
|**Ingestion**|**Winlogbeat (v8.15.3)**|The dedicated Elastic Beat for shipping Windows event logs.|
|**Analysis**|**Elastic Stack (ELK)**|Elasticsearch for storage and Kibana for visualization (as seen in the screenshot).|
|**Data Source**|**Sysmon**|Optional tool for generating detailed, high-fidelity security event data.|
|**Automation**|**PowerShell**|Used for the `ingest.ps1` batch script to manage file processing and cleanup.|

### 📖 Setup and Execution Guide

#### Prerequisites

1. **Download Winlogbeat:** Get the Windows executable.

> `https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.15.3-windows-x86_64.zip`

1. **Download Sysmon** (Optional for generating test data)
>`https://download.sysinternals.com/files/Sysmon.zip`

2. **Download Sample EVTX Files** (Optional)
> `https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES`

#### 1. Directory Structure

Ensure your project uses the following directory structure:

```
C:\ELK_Forensics
├── Tools
│   ├── Sysmon\
│   └── winlogbeat\
└── Evidence\
    ├── Discovery\
    └── [Other EVTX files]
```

Winlogbeat Configuration: (name it: winlogbeat-forensic.yml):

```yml
# ================= Forensic Ingestion Config =================

# winlogbeat-forensic.yml
winlogbeat.event_logs:
  - name: ${EVTX_FILE}
    no_more_events: stop
    start_at: oldest
    ignore_older: 87600h  # The 10 year fix

winlogbeat.shutdown_timeout: 30s
winlogbeat.registry_file: winlogbeat-forensic.data

# Your Cloud Details
cloud.id: "YOUR_CLOUD_ID_HERE"
cloud.auth: "elastic:YOUR_PASSWORD_HERE"

output.elasticsearch:
  tty: true
#### 2. Install Sysmon (Optional)

Install Sysmon to collect rich security events:
```

and to be saved in:

```sh
C:\ELK_Forensics
├── ├
│   └── winlogbeat\winlogbeat-forensic.yml
```

Install Sysmon to collect rich security events:

```sh
cd C:\ELK_Forensics\Tools\Sysmon
.\Sysmon64.exe -i
```

Run winlogbeat (test with 1 file):

```sh
cd C:\ELK_Forensics\Tools\winlogbeat

Remove-Item ".\data" -Recurse -Force -ErrorAction SilentlyContinue

.\winlogbeat.exe -c .\winlogbeat-forensic.yml -E EVTX_FILE="C:\ELK_Forensics\Evidence\Discovery\discovery_psloggedon.evtx" -e
```

Run winlogbeat (Batch Script, to past directly into powershell or save it as ingest.ps1):

```shell
# ========================================================
#  ELK FORENSIC INGESTOR - BATCH SCRIPT
# ========================================================
$toolPath = "C:\ELK_Forensics\Tools\winlogbeat"
$evidencePath = "C:\ELK_Forensics\Evidence"

Set-Location $toolPath
$files = Get-ChildItem -Path $evidencePath -Recurse -Filter *.evtx

foreach ($file in $files) {
    Write-Host "------------------------------------------------" -ForegroundColor Cyan
    Write-Host "PROCESSING: $($file.Name)" -ForegroundColor Yellow
    
    # CRITICAL: Nuke the registry to force Winlogbeat to treat the file as new
    if (Test-Path ".\data") {
        Remove-Item ".\data" -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Execute Ingestion
    .\winlogbeat.exe -c .\winlogbeat-forensic.yml -E EVTX_FILE="$($file.FullName)"
}

Write-Host "BATCH COMPLETED." -ForegroundColor Green
```

Save the script as `ingest.ps1` and save it in:

```sh
C:\ELK_Forensics
├── ├
│   └── ingest.ps1
```

to run in **Powershell**:

```sh
cd C:\ELK_Forensics
.\ingest.ps1
```

To clean Logs from elastic head to the Developper Tools an past the following line, then execute:

```
DELETE _data_stream/winlogbeat-*
```

Source files [Repository][link-repo].
[link-repo]: https://github.com/uzaaz/elastic-evtx-ingestion

---
