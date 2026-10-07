"""Hand-written applicability conditions for the eight official case-study CVEs.

Every condition is transcribed from the CVE description (quoted in `source`), not
from CVSS, so a reviewer can check each one against the record. Wherever the record
leaves something open, the condition is deliberately permissive and the gap is noted
in `note` -- the reference engine must not claim more than the source supports.

These conditions define what "consistent with the environment" means in E1. They do
not establish that an exploit works in practice (backports, hidden configuration and
unstable PoCs are out of scope).
"""

from __future__ import annotations

from dataclasses import dataclass

LEVELS = {"info": 0, "user": 1, "admin": 2}


def parse_version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


@dataclass(frozen=True)
class VersionRange:
    """Half-open or closed bounds over dotted numeric versions; None = unbounded."""

    min_incl: str | None = None
    min_excl: str | None = None
    max_incl: str | None = None
    max_excl: str | None = None

    def contains(self, version: str) -> bool:
        v = parse_version(version)
        if self.min_incl is not None and v < parse_version(self.min_incl):
            return False
        if self.min_excl is not None and v <= parse_version(self.min_excl):
            return False
        if self.max_incl is not None and v > parse_version(self.max_incl):
            return False
        if self.max_excl is not None and v >= parse_version(self.max_excl):
            return False
        return True


@dataclass(frozen=True)
class CveCondition:
    cve_id: str
    service: str  # key of Host.services
    versions: VersionRange | tuple[str, ...]  # range, or the exact allowed values
    access: str  # network | local | physical | line_of_sight
    requires: tuple[tuple[str, bool], ...]  # (host flag, expected value)
    effect: str  # info | user | admin
    source: str
    note: str = ""

    def version_affected(self, version: str) -> bool:
        if isinstance(self.versions, tuple):
            return version in self.versions
        return self.versions.contains(version)


CONDITIONS: dict[str, CveCondition] = {
    c.cve_id: c
    for c in [
        CveCondition(
            "CVE-2019-20354",
            service="pisignage",
            versions=VersionRange(max_excl="2.6.4"),
            access="network",
            requires=(("attacker_has_low_priv_credential", True),),
            effect="info",
            source="piSignage before 2.6.4 allows a remote attacker (authenticated as a "
            "low-privilege user) to download arbitrary files ... via api/settings/log?file=../",
            note="Arbitrary file read only; the record does not say what the files contain, "
            "so no foothold is granted.",
        ),
        CveCondition(
            "CVE-2019-3562",
            service="oculus_browser",
            versions=VersionRange(min_incl="5.2.7", max_incl="5.7.11"),
            access="network",
            requires=(("user_visits_untrusted_pages", True),),
            effect="user",
            source="A remote web page could inject arbitrary HTML code into the Oculus Browser "
            "UI, allowing an attacker to spoof UI and potentially execute code. ... from "
            "version 5.2.7 until 5.7.11.",
            note="'potentially execute code': user-level foothold is the generous reading. "
            "Requires the victim to open an attacker-controlled page (inferred from 'remote "
            "web page').",
        ),
        CveCondition(
            "CVE-2020-1885",
            service="oculus_desktop",
            versions=VersionRange(max_excl="1.44.0.32849"),
            access="local",
            requires=(("os_windows", True),),
            effect="admin",
            source="Writing to an unprivileged file from a privileged OVRRedir.exe process in "
            "Oculus Desktop before 1.44.0.32849 on Windows allows local users to ... gain "
            "privileges via vectors involving a hard link to a log file.",
            note="The CVE record's version field has a typo (1.44.0.328549); the description "
            "is used. 'gain privileges' is read as admin.",
        ),
        CveCondition(
            "CVE-2020-24572",
            service="raspap",
            versions=("2.5",),
            access="network",
            requires=(("attacker_has_low_priv_credential", True),),
            effect="user",
            source="includes/webconsole.php in RaspAP 2.5. With authenticated access, an "
            "attacker can use a misconfigured (and virtually unrestricted) web console to "
            "attack the underlying OS ... and execute commands on the system",
            note="Privilege of the executed commands is not stated in the record, so only a "
            "user-level foothold is granted.",
        ),
        CveCondition(
            "CVE-2021-24038",
            service="oculus_desktop",
            versions=VersionRange(min_excl="1.39", max_excl="31.1.0.67.507"),
            access="local",
            requires=(),
            effect="admin",
            source="OVRServiceLauncher.exe exposes a privileged process handle to an "
            "unprivileged process, leading to local privilege escalation. ... versions after "
            "1.39 and prior to 31.1.0.67.507.",
        ),
        CveCondition(
            "CVE-2021-38545",
            service="raspberry_pi_hw",
            versions=("3B+", "4B"),
            access="line_of_sight",
            requires=(("audio_output_attached", True),),
            effect="info",
            source="Raspberry Pi 3 B+ and 4 B devices ... in certain specific use cases in "
            "which the device supplies power to audio-output equipment, allow remote "
            "attackers to recover speech signals from an LED ... via a telescope and an "
            "electro-optical sensor",
            note="Needs optical line of sight to the device; modelled as the host flag-based "
            "access type 'line_of_sight'.",
        ),
        CveCondition(
            "CVE-2021-38759",
            service="raspberry_pi_os",
            versions=VersionRange(max_incl="5.10"),
            access="network",
            requires=(("pi_default_password_unchanged", True),),
            effect="admin",
            source="Raspberry Pi OS through 5.10 has the raspberry default password for the "
            "pi account. If not changed, attackers can gain administrator privileges.",
            note="The record does not name a remote service (e.g. SSH); network reachability "
            "of the host is assumed.",
        ),
        CveCondition(
            "CVE-2022-21819",
            service="jetson_linux",
            versions=VersionRange(min_incl="32.0", max_excl="32.7.1"),
            access="physical",
            requires=(),
            effect="admin",
            source="NVIDIA distributions of Jetson Linux ... an error in the IOMMU "
            "configuration may allow an unprivileged attacker with physical access to the "
            "board direct read/write access to the entire system address space ... All 32.x "
            "versions prior to 32.7.1",
            note="The record lists Jetson Nano / Nano 2GB, so the service is Jetson Linux on "
            "such a board; nothing is claimed for Jetson TX1.",
        ),
    ]
}
