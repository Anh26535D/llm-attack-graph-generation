"""Small synthetic environments and counterfactual interventions for E1.

An environment is a fully known state S: hosts, installed software with versions,
configuration flags, who can reach whom, and where the attacker starts. Because S is
explicit, the reference engine can say exactly which (CVE, host) pairs are enabled,
and an intervention changes S in a controlled way.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class Host:
    name: str
    description: str  # e.g. "Raspberry Pi 3 B+ running Raspberry Pi OS"
    services: dict[str, str] = field(default_factory=dict)  # service key -> version
    flags: dict[str, bool] = field(default_factory=dict)
    internet_exposed: bool = False  # attacker can reach this host's services directly
    physical_access: bool = False  # attacker is physically at the device
    line_of_sight: bool = False  # attacker has optical line of sight to the device


@dataclass
class Env:
    env_id: str
    title: str
    hosts: dict[str, Host]
    links: set[tuple[str, str]] = field(default_factory=set)  # (from_host, to_host) reachable
    initial_footholds: dict[str, str] = field(default_factory=dict)  # host -> level


@dataclass(frozen=True)
class Intervention:
    name: str
    description: str  # sentence added to the target-system text for the changed state
    apply: Callable[[Env], None]  # mutates a deep copy


def _env_signage() -> Env:
    return Env(
        env_id="signage",
        title="Digital-signage player",
        hosts={
            "signage-pi": Host(
                name="signage-pi",
                description="Raspberry Pi 3 B+ (audio amplifier attached) running Raspberry Pi OS",
                services={
                    "raspberry_pi_hw": "3B+",
                    "raspberry_pi_os": "5.10",
                    "pisignage": "2.6.1",
                    "raspap": "2.5",
                },
                flags={
                    "pi_default_password_unchanged": True,
                    "attacker_has_low_priv_credential": True,
                    "audio_output_attached": True,
                },
                internet_exposed=True,
                line_of_sight=True,
            )
        },
    )


def _env_vr() -> Env:
    return Env(
        env_id="vr",
        title="VR workstation",
        hosts={
            "vr-pc": Host(
                name="vr-pc",
                description="Windows 10 PC used with a VR headset",
                services={"oculus_desktop": "1.40.0.1", "oculus_browser": "5.5.0"},
                flags={"os_windows": True, "user_visits_untrusted_pages": True},
                internet_exposed=True,
            )
        },
    )


def _env_edge() -> Env:
    return Env(
        env_id="edge",
        title="Edge-AI box next to a signage player",
        hosts={
            "jetson": Host(
                name="jetson",
                description="NVIDIA Jetson Nano board running Jetson Linux",
                services={"jetson_linux": "32.6.1"},
                physical_access=True,
            ),
            "signage-pi": Host(
                name="signage-pi",
                description="Raspberry Pi 4 B running Raspberry Pi OS",
                services={
                    "raspberry_pi_hw": "4B",
                    "raspberry_pi_os": "5.10",
                    "raspap": "2.5",
                },
                flags={
                    "pi_default_password_unchanged": True,
                    "attacker_has_low_priv_credential": True,
                },
            ),
        },
        links={("jetson", "signage-pi")},
    )


ENV_FACTORIES = {"signage": _env_signage, "vr": _env_vr, "edge": _env_edge}


def _set_version(host: str, service: str, version: str) -> Callable[[Env], None]:
    def apply(env: Env) -> None:
        env.hosts[host].services[service] = version

    return apply


def _set_flag(host: str, flag: str, value: bool) -> Callable[[Env], None]:
    def apply(env: Env) -> None:
        env.hosts[host].flags[flag] = value

    return apply


def _drop_link(src: str, dst: str) -> Callable[[Env], None]:
    def apply(env: Env) -> None:
        env.links.discard((src, dst))

    return apply


def _set_physical(host: str, value: bool) -> Callable[[Env], None]:
    def apply(env: Env) -> None:
        env.hosts[host].physical_access = value

    return apply


def _set_exposed(host: str, value: bool) -> Callable[[Env], None]:
    def apply(env: Env) -> None:
        env.hosts[host].internet_exposed = value

    return apply


INTERVENTIONS: dict[str, dict[str, Intervention]] = {
    "signage": {
        "patch_pisignage": Intervention(
            "patch_pisignage",
            "piSignage has been upgraded to version 2.6.5.",
            _set_version("signage-pi", "pisignage", "2.6.5"),
        ),
        "change_pi_password": Intervention(
            "change_pi_password",
            "The default password of the 'pi' account has been changed to a strong password.",
            _set_flag("signage-pi", "pi_default_password_unchanged", False),
        ),
        "remove_credential": Intervention(
            "remove_credential",
            "The attacker no longer holds any valid credential for the web applications.",
            _set_flag("signage-pi", "attacker_has_low_priv_credential", False),
        ),
        "no_audio_output": Intervention(
            "no_audio_output",
            "The audio amplifier has been disconnected; the board no longer powers audio equipment.",
            _set_flag("signage-pi", "audio_output_attached", False),
        ),
    },
    "vr": {
        "patch_oculus_desktop": Intervention(
            "patch_oculus_desktop",
            "Oculus Desktop has been updated to version 31.1.0.67.507.",
            _set_version("vr-pc", "oculus_desktop", "31.1.0.67.507"),
        ),
        "update_browser": Intervention(
            "update_browser",
            "Oculus Browser has been updated to version 6.0.0.",
            _set_version("vr-pc", "oculus_browser", "6.0.0"),
        ),
        "block_untrusted_pages": Intervention(
            "block_untrusted_pages",
            "A web filter now prevents users from opening untrusted pages in Oculus Browser.",
            _set_flag("vr-pc", "user_visits_untrusted_pages", False),
        ),
    },
    "edge": {
        "block_jetson_to_pi": Intervention(
            "block_jetson_to_pi",
            "A firewall rule now blocks all traffic from the Jetson board to the signage Pi.",
            _drop_link("jetson", "signage-pi"),
        ),
        "secure_enclosure": Intervention(
            "secure_enclosure",
            "The Jetson board is now in a locked enclosure; the attacker has no physical access.",
            _set_physical("jetson", False),
        ),
        "patch_jetson": Intervention(
            "patch_jetson",
            "Jetson Linux has been upgraded to version 32.7.2.",
            _set_version("jetson", "jetson_linux", "32.7.2"),
        ),
    },
}


def build_env(env_id: str, intervention: str | None = None) -> Env:
    env = ENV_FACTORIES[env_id]()
    if intervention is not None:
        INTERVENTIONS[env_id][intervention].apply(env)
    return copy.deepcopy(env)
