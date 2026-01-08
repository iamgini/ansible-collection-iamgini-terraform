# plugins/inventory/tfe_state.py
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import re
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from ansible.module_utils._text import to_text
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable
from ansible.errors import AnsibleError


DOCUMENTATION = r"""
name: tfe_state
plugin_type: inventory
author:
  - iamgini
short_description: Builds an inventory by downloading Terraform Enterprise/Cloud state via API.
description:
  - Fetches the current state version for a workspace using the Terraform Enterprise (TFE) API.
  - Downloads the hosted state JSON (tfstate) and builds inventory from supported resources.
  - Works without access to Terraform IaC working directory or terraform CLI.

options:
  plugin:
    description: Name of this plugin.
    required: true
    type: str
    choices: ["iamgini.terraform.tfe_state"]

  hostname:
    description: Terraform Enterprise hostname (no scheme). Example terraform-server.awesome.com
    required: true
    type: str

  organization:
    description: Terraform organization name.
    required: true
    type: str

  workspace:
    description: Terraform workspace name.
    required: true
    type: str

  token:
    description:
      - Terraform token. Not recommended to hardcode.
      - Prefer token_env or controller credential injection.
    required: false
    type: str
    no_log: true

  token_env:
    description:
      - Environment variable name that contains the token.
      - Example: TF_TOKEN_terraform_server_awesome_com or TFE_TOKEN
    required: false
    type: str
    default: "TFE_TOKEN"

  verify_ssl:
    description: Verify TLS certificates.
    type: bool
    default: true

  resource_types:
    description:
      - Resource types to include as hosts.
      - Defaults cover common VM resources.
    type: list
    elements: str
    default:
      - aws_instance
      - google_compute_instance
      - azurerm_virtual_machine
      - azurerm_linux_virtual_machine
      - azurerm_windows_virtual_machine

  search_child_modules:
    description:
      - Whether to include resources from Terraform child modules.
    type: bool
    default: false

  hostnames:
    description:
      - Same idea as cloud.terraform.terraform_state hostnames.
      - Examples:
        - ["tag:Name", "private_dns", "id"]
    type: list
    elements: raw
    default: []

extends_documentation_fragment:
  - constructed
"""

EXAMPLES = r"""
# Minimal
plugin: iamgini.terraform.tfe_state
hostname: terraform-server.awesome.com
organization: infra
workspace: nginx-api-infra
token_env: TF_TOKEN_terraform_server_awesome_com
verify_ssl: false
compose:
  ansible_host: private_ip

# Group by tag value
plugin: iamgini.terraform.tfe_state
hostname: terraform-server.awesome.com
organization: infra
workspace: nginx-api-infra
token_env: TF_TOKEN_terraform_server_awesome_com
keyed_groups:
  - key: tags.Environment
    prefix: env
"""

SUPPORTED_TFSTATE_VERSION = 4


def _sanitize_group_name(name: str) -> str:
    # mimic Ansible group sanitization rules enough for inventory usage
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def _sanitize_hostname(name: str) -> str:
    # hostnames cannot contain ":" (Ansible treats it like host:port)
    if ":" in name:
        return _sanitize_group_name(name)
    return name


def _tf_tags(attrs: Dict[str, Any]) -> Dict[str, Any]:
    # aws: tags is dict; other providers vary but many keep "tags"/"labels"
    return attrs.get("tags") or attrs.get("labels") or {}


def _tag_hostname(attrs: Dict[str, Any], preference: str) -> Optional[str]:
    # preference: tag:Name or tag:Name=Value,tag:Other=Val2
    tag_expr = preference.split("tag:", 1)[1]
    candidates = tag_expr.split(",")
    tags = _tf_tags(attrs)

    for c in candidates:
        k_v = c.split("=", 1)
        if len(k_v) == 2:
            k, v = k_v[0], k_v[1]
            if to_text(tags.get(k)) == v:
                return f"{k}_{v}"
        else:
            k = c
            if tags.get(k) is not None:
                return to_text(tags.get(k))
    return None


def _preferred_hostname(resource_type: str, resource_name: str, attrs: Dict[str, Any], hostnames: List[Any]) -> str:
    if not hostnames:
        return f"{resource_type}_{resource_name}"

    for pref in hostnames:
        if isinstance(pref, dict):
            # minimal support for dict form: {name, prefix, separator}
            name_key = pref.get("name")
            if not name_key:
                raise AnsibleError("hostnames dict requires 'name'")
            base = _preferred_hostname(resource_type, resource_name, attrs, [name_key])
            prefix = pref.get("prefix")
            if prefix:
                pfx = _preferred_hostname(resource_type, resource_name, attrs, [prefix])
                sep = pref.get("separator", "_")
                return f"{pfx}{sep}{base}"
            return base

        pref = to_text(pref)
        if pref.startswith("tag:"):
            h = _tag_hostname(attrs, pref)
            if h:
                return h

        # direct attribute name (private_ip, public_ip, name, id, etc.)
        if pref in attrs and attrs.get(pref) not in (None, ""):
            return to_text(attrs.get(pref))

        # literal string fallback
        if pref:
            return pref

    return f"{resource_type}_{resource_name}"


class InventoryModule(BaseInventoryPlugin, Constructable):
    NAME = "iamgini.terraform.tfe_state"

    def verify_file(self, path: str) -> bool:
        if not super().verify_file(path):
            return False
        return path.endswith((".yml", ".yaml"))


    def _http_get_json(self, url: str, token: str, verify_ssl: bool) -> Dict[str, Any]:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/vnd.api+json",
            },
        )

        ctx = None
        if not verify_ssl:
            import ssl
            ctx = ssl._create_unverified_context()

        try:
            with urllib.request.urlopen(req, context=ctx) as resp:
                data = resp.read().decode("utf-8")
                return json.loads(data)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
            raise AnsibleError(f"TFE API HTTP error {e.code} for {url}. Body: {body[:500]}")
        except Exception as e:
            raise AnsibleError(f"Failed calling TFE API {url}: {e}")

    def _download_text(self, url: str, token: str, verify_ssl: bool) -> str:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})

        ctx = None
        if not verify_ssl:
            import ssl
            ctx = ssl._create_unverified_context()

        try:
            with urllib.request.urlopen(req, context=ctx) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
            raise AnsibleError(f"State download HTTP error {e.code}. Body: {body[:500]}")
        except Exception as e:
            raise AnsibleError(f"Failed downloading state: {e}")

    def _get_token(self, cfg: Dict[str, Any]) -> str:
        token = cfg.get("token")
        if token:
            return token

        env_name = cfg.get("token_env", "TFE_TOKEN")
        token = os.environ.get(env_name)
        if token:
            return token

        raise AnsibleError(
            f"Token not found. Provide 'token', or set env var '{env_name}' (token_env), or inject via Controller credential."
        )

    def _fetch_tfstate(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        host = cfg["hostname"]
        org = cfg["organization"]
        ws = cfg["workspace"]
        verify_ssl = bool(cfg.get("verify_ssl", True))
        token = self._get_token(cfg)

        base = f"https://{host}/api/v2"

        # 1) workspace -> workspace id
        ws_url = f"{base}/organizations/{org}/workspaces/{ws}"
        ws_doc = self._http_get_json(ws_url, token, verify_ssl)
        ws_id = ws_doc["data"]["id"]

        # 2) current state version -> hosted download url
        csv_url = f"{base}/workspaces/{ws_id}/current-state-version"
        csv_doc = self._http_get_json(csv_url, token, verify_ssl)
        download_url = csv_doc["data"]["attributes"].get("hosted-state-download-url")
        if not download_url:
            raise AnsibleError("No hosted-state-download-url returned. Workspace may have no state yet.")

        # 3) download state JSON
        raw = self._download_text(download_url, token, verify_ssl)
        tfstate = json.loads(raw)

        if tfstate.get("version") != SUPPORTED_TFSTATE_VERSION:
            # Don’t fail; just warn
            self.display.warning(
                f"tfstate version is {tfstate.get('version')}; plugin is tested mainly with version {SUPPORTED_TFSTATE_VERSION}."
            )

        return tfstate

    def _iter_instances(self, tfstate: Dict[str, Any], search_child_modules: bool, resource_types: List[str]):
        for r in tfstate.get("resources", []):
            if not search_child_modules and r.get("module"):
                continue
            if r.get("type") not in resource_types:
                continue
            for inst in r.get("instances", []):
                attrs = inst.get("attributes") or {}
                yield r, attrs

    def parse(self, inventory, loader, path, cache=False):
        super().parse(inventory, loader, path, cache=cache)
        cfg = self._read_config_data(path)

        # required
        for k in ("hostname", "organization", "workspace"):
            if not cfg.get(k):
                raise AnsibleError(f"Missing required option: {k}")

        tfstate = self._fetch_tfstate(cfg)

        resource_types = cfg.get("resource_types") or []
        search_child_modules = bool(cfg.get("search_child_modules", False))
        hostnames = cfg.get("hostnames") or []

        compose = cfg.get("compose")
        keyed_groups = cfg.get("keyed_groups") or []
        groups = cfg.get("groups") or {}
        strict = cfg.get("strict")

        added = 0
        for r, attrs in self._iter_instances(tfstate, search_child_modules, resource_types):
            name = _preferred_hostname(r.get("type", "resource"), r.get("name", "unknown"), attrs, hostnames)
            name = _sanitize_hostname(to_text(name))

            self.inventory.add_host(name)
            added += 1

            # set hostvars from tf attributes
            for k, v in attrs.items():
                self.inventory.set_variable(name, k, v)

            # constructed features
            self._set_composite_vars(compose, attrs, name, strict=strict)
            self._add_host_to_keyed_groups(keyed_groups, attrs, name, strict=strict)
            self._add_host_to_composed_groups(groups, attrs, name, strict=strict)

        if added == 0:
            self.display.warning(
                "No hosts added. Either the workspace state has no matching resource_types, "
                "or instances are created indirectly (e.g., ASG/EKS) and not present as aws_instance."
            )
            raise AnsibleError(
                "No hosts were discovered from Terraform state. "
                "Check resource_types and module filtering."
            )
