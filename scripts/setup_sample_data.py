#!/usr/bin/env python
"""Step 0 (optional): materialize the bundled sample dataset on disk.

The 8 sample CVE records and 3 threat-report excerpts used by
`quickstart_demo.py` / the README examples are NOT committed to git as
`.json`/`.txt` files — they are reconstructed here from literal Python data
so the repository doesn't carry a data dump. Run this once after cloning:

    uv run python scripts/setup_sample_data.py

For REAL CVE/threat-report data instead of this bundled example set, see
the "Nguon du lieu" section of the README (MITRE cvelistV5, NVD API,
cve.org, or any threat-intel report saved as .txt) and point
`scripts/ingest_cves.py --input` / `scripts/build_prompt.py --report` at
your own files -- nothing about the pipeline is specific to this sample set.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crystalball.config import DATA_DIR  # noqa: E402

CVE_SAMPLES_DIR = DATA_DIR / "cve_samples"
THREAT_REPORTS_DIR = DATA_DIR / "threat_reports"

# --- CVE Record Format v5 samples ------------------------------------------
# Reproduces the 8-vulnerability "Oculus Desktop / Jetson TX1 / Raspberry Pi"
# example system from Appendix A of the paper. Two CVE IDs are confirmed by
# the paper itself (CVE-2020-25299 for piSignage, CVE-2020-1885 for
# OVRRedir.exe, shown in Figure 1); the rest are placeholder IDs
# (CVE-2024-900xx) assigned for this reproduction only -- see README below.

SAMPLE_CVES: dict[str, dict] = {
    "CVE-2020-25299.json": {
        "cveMetadata": {"cveId": "CVE-2020-25299", "state": "PUBLISHED", "assignerOrgId": "sample-data"},
        "containers": {
            "cna": {
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "The web application component of piSignage before 2.6.4 allows a "
                            "remote attacker (authenticated as a low-privilege user) to download "
                            "arbitrary files from the Raspberry Pi via api/settings/log?file=../ "
                            "path traversal. In other words, this issue is in the player API for "
                            "log download."
                        ),
                    }
                ],
                "affected": [
                    {
                        "vendor": "piSignage",
                        "product": "piSignage",
                        "platforms": ["Raspberry Pi OS"],
                        "versions": [{"version": "2.6.4", "lessThan": "2.6.4", "versionType": "custom"}],
                    }
                ],
                "problemTypes": [{"descriptions": [{"lang": "en", "description": "Path Traversal (CWE-22)"}]}],
            }
        },
    },
    "CVE-2024-90001.json": {
        "cveMetadata": {"cveId": "CVE-2024-90001", "state": "PUBLISHED", "assignerOrgId": "sample-data"},
        "containers": {
            "cna": {
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "A remote web page could inject arbitrary HTML code into the Oculus "
                            "Browser UI, allowing an attacker to spoof UI and potentially execute "
                            "code. This affects the Oculus Browser starting from version 5.2.7 "
                            "until 5.7.11."
                        ),
                    }
                ],
                "affected": [
                    {
                        "vendor": "Meta",
                        "product": "Oculus Browser",
                        "platforms": [],
                        "versions": [{"version": "5.2.7", "lessThan": "5.7.11", "versionType": "custom"}],
                    }
                ],
                "problemTypes": [
                    {"descriptions": [{"lang": "en", "description": "HTML Injection / UI Spoofing (CWE-79)"}]}
                ],
            }
        },
    },
    "CVE-2020-1885.json": {
        "cveMetadata": {"cveId": "CVE-2020-1885", "state": "PUBLISHED", "assignerOrgId": "sample-data"},
        "containers": {
            "cna": {
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "Writing to an unprivileged file from a privileged OVRRedir.exe "
                            "process in Oculus Desktop before 1.44.0.32849 on Windows allows "
                            "local users to write to arbitrary files and consequently gain "
                            "privileges via vectors involving a hard link to a log file."
                        ),
                    }
                ],
                "affected": [
                    {
                        "vendor": "Meta",
                        "product": "Oculus Desktop",
                        "platforms": ["Windows"],
                        "versions": [
                            {"version": "1.44.0.32849", "lessThan": "1.44.0.32849", "versionType": "custom"}
                        ],
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {"lang": "en", "description": "Privilege Escalation via Arbitrary File Write (CWE-732)"}
                        ]
                    }
                ],
            }
        },
    },
    "CVE-2024-90002.json": {
        "cveMetadata": {"cveId": "CVE-2024-90002", "state": "PUBLISHED", "assignerOrgId": "sample-data"},
        "containers": {
            "cna": {
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "An issue was discovered in includes/webconsole.php in RaspAP 2.5. "
                            "With authenticated access, an attacker can use a misconfigured (and "
                            "virtually unrestricted) web console to attack the underlying OS "
                            "(Raspberry Pi) running this software, and execute commands on the "
                            "system (including ones for uploading of files and execution of code)."
                        ),
                    }
                ],
                "affected": [
                    {
                        "vendor": "RaspAP",
                        "product": "RaspAP",
                        "platforms": ["Raspberry Pi OS"],
                        "versions": [{"version": "2.5", "versionType": "custom"}],
                    }
                ],
                "problemTypes": [{"descriptions": [{"lang": "en", "description": "OS Command Injection (CWE-78)"}]}],
            }
        },
    },
    "CVE-2024-90003.json": {
        "cveMetadata": {"cveId": "CVE-2024-90003", "state": "PUBLISHED", "assignerOrgId": "sample-data"},
        "containers": {
            "cna": {
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "Due to a bug with management of handles in OVRServiceLauncher.exe, "
                            "an attacker could expose a privileged process handle to an "
                            "unprivileged process, leading to local privilege escalation. This "
                            "issue affects Oculus Desktop versions after 1.39 and prior to "
                            "31.1.0.67.507."
                        ),
                    }
                ],
                "affected": [
                    {
                        "vendor": "Meta",
                        "product": "Oculus Desktop",
                        "platforms": ["Windows"],
                        "versions": [
                            {"version": "1.39", "lessThan": "31.1.0.67.507", "versionType": "custom"}
                        ],
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {"lang": "en", "description": "Improper Handle Management leading to Privilege Escalation (CWE-269)"}
                        ]
                    }
                ],
            }
        },
    },
    "CVE-2024-90004.json": {
        "cveMetadata": {"cveId": "CVE-2024-90004", "state": "PUBLISHED", "assignerOrgId": "sample-data"},
        "containers": {
            "cna": {
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "Raspberry Pi 3 B+ and 4 B devices through 2021-08-09, in certain "
                            "specific use cases in which the device supplies power to "
                            "audio-output equipment, allow remote attackers to recover speech "
                            "signals from an LED on the device, via a telescope and an "
                            "electro-optical sensor, aka a \"Glowworm\" attack. We assume that the "
                            "Raspberry Pi supplies power to some speakers. The power indicator "
                            "LED of the Raspberry Pi is connected directly to the power line, as "
                            "a result, the intensity of a device's power indicator LED is "
                            "correlative to the power consumption. The sound played by the "
                            "speakers affects the Raspberry Pi's power consumption and as a "
                            "result is also correlative to the light intensity of the LED. By "
                            "analyzing measurements obtained from an electro-optical sensor "
                            "directed at the power indicator LED of the Raspberry Pi, we can "
                            "recover the sound played by the speakers."
                        ),
                    }
                ],
                "affected": [
                    {
                        "vendor": "Raspberry Pi Foundation",
                        "product": "Raspberry Pi 3 B+/4 B",
                        "platforms": [],
                        "versions": [{"version": "through 2021-08-09", "versionType": "custom"}],
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {"lang": "en", "description": "Side-Channel Information Leakage via Optical Emanation (CWE-1300)"}
                        ]
                    }
                ],
            }
        },
    },
    "CVE-2024-90005.json": {
        "cveMetadata": {"cveId": "CVE-2024-90005", "state": "PUBLISHED", "assignerOrgId": "sample-data"},
        "containers": {
            "cna": {
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "Raspberry Pi OS through 5.10 has the raspberry default password for "
                            "the pi account. If not changed, attackers can gain administrator "
                            "privileges."
                        ),
                    }
                ],
                "affected": [
                    {
                        "vendor": "Raspberry Pi Foundation",
                        "product": "Raspberry Pi OS",
                        "platforms": ["Raspberry Pi OS"],
                        "versions": [{"version": "through 5.10", "versionType": "custom"}],
                    }
                ],
                "problemTypes": [
                    {"descriptions": [{"lang": "en", "description": "Use of Default Credentials (CWE-1392)"}]}
                ],
            }
        },
    },
    "CVE-2024-90006.json": {
        "cveMetadata": {"cveId": "CVE-2024-90006", "state": "PUBLISHED", "assignerOrgId": "sample-data"},
        "containers": {
            "cna": {
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "NVIDIA distributions of Jetson Linux contain a vulnerability where "
                            "an error in the IOMMU configuration may allow an unprivileged "
                            "attacker with physical access to the board direct read/write access "
                            "to the entire system address space through the PCI bus. Such an "
                            "attack could result in denial of service, code execution, escalation "
                            "of privileges, and impact to data integrity and confidentiality. The "
                            "scope impact may extend to other components."
                        ),
                    }
                ],
                "affected": [
                    {
                        "vendor": "NVIDIA",
                        "product": "Jetson Linux",
                        "platforms": ["Linux"],
                        "versions": [{"version": "all", "versionType": "custom"}],
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {"lang": "en", "description": "Improper IOMMU Configuration leading to Privilege Escalation (CWE-1247)"}
                        ]
                    }
                ],
            }
        },
    },
}

# --- Threat report excerpts --------------------------------------------------
# Quoted from Appendix B/C of the paper (originally FireEye/Mandiant's
# SolarWinds report and Microsoft's Kubernetes cluster write-up).

SAMPLE_REPORTS: dict[str, str] = {
    "kubernetes_cluster_hacked.txt": (
        "The security researchers at Microsoft analyzed the attack and identified two attack "
        "paths were used. The first attack path is establishing and enumerating the PostgreSQL "
        "servers that had configuration issues. From there one of the most common "
        "misconfigurations that were being exploited is the \"trust authentication\" setting "
        "which allows PostgreSQL to make an assumption that any connection that is established "
        "towards the server is authorized to get database access. In addition, if a security "
        "issue exists such that a broad range of IP addresses are being assigned then any IP "
        "address that the attacker may be using can be used to gain access to the server. The "
        "second attack path is trying to exploit a security flaw in container images. In this "
        "particular scenario, the attackers are searching for a remote code execution "
        "vulnerability which will then allow them to push their payload and gain access to the "
        "server in that manner. From what has been seen so far, the attackers are trying to find "
        "and exploit security flaws in these applications: WordPress Liferay PHPUnit Oracle "
        "WebLogic.\n"
    ),
    "solarwinds_evasion.txt": (
        "We are currently tracking the software supply chain compromise and related post "
        "intrusion activity as UNC2452. After gaining initial access, this group uses a variety "
        "of techniques to disguise their operations while they move laterally (Figure 2). This "
        "actor prefers to maintain a light malware footprint, instead preferring legitimate "
        "credentials and remote access for access into a victim's environment.\n\n"
        "Post-compromise tactics\n\n"
        "TEARDROP and BEACON Malware Used\n"
        "Multiple SUNBURST samples have been recovered, delivering different payloads. In at "
        "least one instance the attackers deployed a previously unseen memory-only dropper we've "
        "dubbed TEARDROP to deploy Cobalt Strike BEACON. TEARDROP is a memory only dropper that "
        "runs as a service, spawns a thread and reads from the file \"gracious_truth.jpg\", which "
        "likely has a fake JPG header. Next it checks that HKU\\SOFTWARE\\Microsoft\\CTF exists, "
        "decodes an embedded payload using a custom rolling XOR algorithm and manually loads into "
        "memory an embedded payload using a custom PE-like file format. TEARDROP does not have "
        "code overlap with any previously seen malware. We believe that this was used to execute "
        "a customized Cobalt Strike BEACON.\n\n"
        "Attacker Hostnames Match Victim Environment\n"
        "The actor sets the hostnames on their command and control infrastructure to match a "
        "legitimate hostname found within the victim's environment. This allows the adversary to "
        "blend into the environment, avoid suspicion, and evade detection.\n\n"
        "IP Addresses located in Victim's Country\n"
        "The attacker's choice of IP addresses was also optimized to evade detection. The "
        "attacker primarily used only IP addresses originating from the same country as the "
        "victim, leveraging Virtual Private Servers.\n\n"
        "Lateral Movement Using Different Credentials\n"
        "Once the attacker gained access to the network with compromised credentials, they moved "
        "laterally using multiple different credentials. The credentials used for lateral "
        "movement were always different from those used for remote access.\n\n"
        "Temporary File Replacement and Temporary Task Modification\n"
        "The attacker used a temporary file replacement technique to remotely execute utilities: "
        "they replaced a legitimate utility with theirs, executed their payload, and then "
        "restored the legitimate original file. They similarly manipulated scheduled tasks by "
        "updating an existing legitimate task to execute their tools and then returning the "
        "scheduled task to its original configuration. They routinely removed their tools, "
        "including removing backdoors once legitimate remote access was achieved.\n"
    ),
}

# The full SolarWinds report is long; kept separate for readability.
SAMPLE_REPORTS["solarwinds_full.txt"] = (
    "Executive Summary\n"
    "We have discovered a global intrusion campaign. We are tracking the actors behind this "
    "campaign as UNC2452. FireEye discovered a supply chain attack trojanizing SolarWinds Orion "
    "business software updates in order to distribute malware we call SUNBURST. The attacker's "
    "post compromise activity leverages multiple techniques to evade detection and obscure their "
    "activity, but these efforts also offer some opportunities for detection. The campaign is "
    "widespread, affecting public and private organizations around the world.\n\n"
    "Summary\n"
    "FireEye has uncovered a widespread campaign, that we are tracking as UNC2452. The actors "
    "behind this campaign gained access to numerous public and private organizations around the "
    "world. They gained access to victims via trojanized updates to SolarWind's Orion IT "
    "monitoring and management software. This campaign may have begun as early as Spring 2020 "
    "and is currently ongoing. Post compromise activity following this supply chain compromise "
    "has included lateral movement and data theft.\n\n"
    "SUNBURST Backdoor\n"
    "SolarWinds.Orion.Core.BusinessLayer.dll is a SolarWinds digitally-signed component of the "
    "Orion software framework that contains a backdoor that communicates via HTTP to third party "
    "servers. We are tracking the trojanized version of this SolarWinds Orion plug-in as "
    "SUNBURST. After an initial dormant period of up to two weeks, it retrieves and executes "
    "commands, called \"Jobs\", that include the ability to transfer files, execute files, profile "
    "the system, reboot the machine, and disable system services. The malware masquerades its "
    "network traffic as the Orion Improvement Program (OIP) protocol and stores reconnaissance "
    "results within legitimate plugin configuration files allowing it to blend in with legitimate "
    "SolarWinds activity.\n\n"
    "Post Compromise Activity and Detection Opportunities\n"
    "After gaining initial access, this group uses a variety of techniques to disguise their "
    "operations while they move laterally. This actor prefers to maintain a light malware "
    "footprint, instead preferring legitimate credentials and remote access for access into a "
    "victim's environment.\n\n"
    "TEARDROP and BEACON Malware Used\n"
    "Multiple SUNBURST samples have been recovered, delivering different payloads. In at least "
    "one instance the attackers deployed a previously unseen memory-only dropper we've dubbed "
    "TEARDROP to deploy Cobalt Strike BEACON. TEARDROP is a memory only dropper that runs as a "
    "service, spawns a thread and reads from the file \"gracious_truth.jpg\", which likely has a "
    "fake JPG header. Next it checks that HKU\\SOFTWARE\\Microsoft\\CTF exists, decodes an "
    "embedded payload using a custom rolling XOR algorithm and manually loads into memory an "
    "embedded payload using a custom PE-like file format.\n\n"
    "Attacker Hostnames Match Victim Environment\n"
    "The actor sets the hostnames on their command and control infrastructure to match a "
    "legitimate hostname found within the victim's environment, to blend in and evade detection.\n\n"
    "IP Addresses located in Victim's Country\n"
    "The attacker primarily used only IP addresses originating from the same country as the "
    "victim, leveraging Virtual Private Servers.\n\n"
    "Lateral Movement Using Different Credentials\n"
    "Once the attacker gained access to the network with compromised credentials, they moved "
    "laterally using multiple different credentials, always different from those used for remote "
    "access.\n\n"
    "Temporary File Replacement and Temporary Task Modification\n"
    "The attacker used a temporary file replacement technique to remotely execute utilities: they "
    "replaced a legitimate utility with theirs, executed their payload, and then restored the "
    "legitimate original file. They similarly manipulated scheduled tasks, and routinely removed "
    "their tools, including removing backdoors once legitimate remote access was achieved.\n\n"
    "In-Depth Malware Analysis\n"
    "SolarWinds.Orion.Core.BusinessLayer.dll (b91ce2fa41029f6955bff20079468448) is a "
    "SolarWinds-signed plugin component of the Orion software framework that contains an "
    "obfuscated backdoor which communicates via HTTP to third party servers. The backdoor "
    "determines its C2 server using a Domain Generation Algorithm (DGA) to construct and resolve "
    "a subdomain of avsvmcloud[.]com. Process name, service name, and driver path listings are "
    "obtained and checked against hardcoded blocklists to evade forensic and anti-virus tools.\n\n"
    "Network Command and Control (C2)\n"
    "If all blocklist and connectivity checks pass, the sample starts generating domains via its "
    "DGA and spawns a new thread invoking HttpHelper.Initialize, responsible for all C2 "
    "communications. Malware response messages are DEFLATE compressed and single-byte-XOR "
    "encoded, then split among fields in a JSON payload disguised as legitimate telemetry.\n\n"
    "Supported backdoor commands include: Idle, Exit, SetTime, CollectSystemDescription, "
    "UploadSystemDescription, RunTask, GetProcessByDescription, KillTask, GetFileSystemEntries, "
    "WriteFile, FileExists, DeleteFile, GetFileHash, ReadRegistryValue, SetRegistryValue, "
    "DeleteRegistryValue, GetRegistrySubKeyAndValueNames, and Reboot.\n\n"
    "MITRE ATT&CK Techniques Observed: T1012 Query Registry, T1027 Obfuscated Files or "
    "Information, T1057 Process Discovery, T1070.004 File Deletion, T1071.001 Web Protocols, "
    "T1071.004 Application Layer Protocol: DNS, T1083 File and Directory Discovery, T1105 "
    "Ingress Tool Transfer, T1132.001 Standard Encoding, T1195.002 Compromise Software Supply "
    "Chain, T1518 Software Discovery, T1518.001 Security Software Discovery, T1543.003 Windows "
    "Service, T1553.002 Code Signing, T1568.002 Domain Generation Algorithms, T1569.002 Service "
    "Execution, T1584 Compromise Infrastructure.\n\n"
    "Immediate Mitigation Recommendations\n"
    "Organizations should isolate SolarWinds servers, block Internet egress from them, restrict "
    "the scope of accounts with local administrator privilege on them, and change passwords for "
    "accounts with access to SolarWinds infrastructure, pending a full investigation.\n"
)


def main() -> None:
    CVE_SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    THREAT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    for filename, record in SAMPLE_CVES.items():
        path = CVE_SAMPLES_DIR / filename
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        print(f"  wrote {path}")

    for filename, text in SAMPLE_REPORTS.items():
        path = THREAT_REPORTS_DIR / filename
        path.write_text(text, encoding="utf-8")
        print(f"  wrote {path}")

    print(
        f"\nDone: {len(SAMPLE_CVES)} sample CVE record(s) in {CVE_SAMPLES_DIR}, "
        f"{len(SAMPLE_REPORTS)} sample threat report(s) in {THREAT_REPORTS_DIR}."
    )


if __name__ == "__main__":
    main()
