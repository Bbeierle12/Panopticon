"""Nmap network scanner adapter."""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from netsec.adapters.base import BaseAdapter, ToolCategory, ToolInfo, ToolStatus
from netsec.adapters.process import check_binary, get_binary_version, quote_path, run_command
from netsec.platform.paths import find_tool_binary

logger = logging.getLogger(__name__)


class Adapter(BaseAdapter):
    """Nmap network scanner adapter."""

    def __init__(self) -> None:
        self._binary: str | None = None
        self._version: str | None = None
        self._status = ToolStatus.UNKNOWN

    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="nmap",
            display_name="Nmap",
            category=ToolCategory.NETWORK_SCANNER,
            description="Network exploration and security auditing tool",
            version=self._version,
            binary_path=self._binary,
            status=self._status,
            supported_tasks=["quick_scan", "full_scan", "port_scan", "os_detect", "service_detect", "vuln_scan"],
        )

    async def detect(self) -> bool:
        self._binary = find_tool_binary("nmap")
        if self._binary is None:
            # Fallback to PATH
            self._binary = await check_binary("nmap") if not self._binary else self._binary
        if self._binary:
            version_str = await get_binary_version(self._binary)
            if version_str:
                # Parse "Nmap version 7.94 ( https://nmap.org )"
                parts = version_str.split()
                for i, p in enumerate(parts):
                    if p == "version" and i + 1 < len(parts):
                        self._version = parts[i + 1]
                        break
                if not self._version:
                    self._version = version_str.split("\n")[0]
            self._status = ToolStatus.AVAILABLE
            return True
        self._status = ToolStatus.UNAVAILABLE
        return False

    async def health_check(self) -> ToolStatus:
        if not self._binary:
            return ToolStatus.UNAVAILABLE
        quoted = quote_path(self._binary)
        result = await run_command(f"{quoted} --version", timeout=10)
        self._status = ToolStatus.AVAILABLE if result.success else ToolStatus.ERROR
        return self._status

    async def execute(self, task: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self._binary:
            raise RuntimeError("Nmap is not available")

        target = params.get("target", "")
        if not target:
            raise ValueError("Target is required")

        timeout = params.get("timeout", 300)
        cmd = self._build_command(task, params)

        logger.info("Executing Nmap: %s", cmd)
        result = await run_command(cmd, timeout=timeout)

        if result.timed_out:
            return {"error": "Scan timed out", "command": cmd}

        if not result.success:
            return {"error": result.stderr, "command": cmd, "returncode": result.returncode}

        # Parse XML output
        parsed = await self.parse_output(result.stdout, output_format="xml")
        parsed["command"] = cmd
        return parsed

    def _build_command(self, task: str, params: dict[str, Any]) -> str:
        target = params["target"]
        binary = quote_path(self._binary) if self._binary else "nmap"

        # Always output XML to stdout
        base = f"{binary} -oX -"

        match task:
            case "quick_scan":
                # Host discovery + top 100 ports + service detection for device classification
                return f"{base} -F -sV --version-intensity 2 -T4 {target}"
            case "discovery":
                # Ping sweep only (no port scan)
                return f"{base} -sn {target}"
            case "full_scan":
                return f"{base} -sV -O -A {target}"
            case "port_scan":
                ports = params.get("ports", "1-1024")
                return f"{base} -sS -p {ports} {target}"
            case "os_detect":
                return f"{base} -O {target}"
            case "service_detect":
                return f"{base} -sV {target}"
            case "vuln_scan":
                return f"{base} --script vuln {target}"
            case _:
                # Custom command parts
                extra = params.get("args", "")
                return f"{base} {extra} {target}"

    async def parse_output(self, raw_output: str | bytes, output_format: str = "text") -> dict[str, Any]:
        if output_format == "xml" or (isinstance(raw_output, str) and raw_output.strip().startswith("<?xml")):
            return self._parse_xml(raw_output if isinstance(raw_output, str) else raw_output.decode(errors="replace"))
        return {"raw": raw_output}

    def _parse_xml(self, xml_str: str) -> dict[str, Any]:
        """Parse Nmap XML output into structured data."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            logger.warning("Failed to parse Nmap XML: %s", e)
            return {"error": f"XML parse error: {e}", "raw": xml_str[:2000]}

        result: dict[str, Any] = {
            "scan_info": {},
            "hosts": [],
            "stats": {},
        }

        # Scan info
        scanner = root.attrib
        result["scan_info"] = {
            "scanner": scanner.get("scanner", "nmap"),
            "args": scanner.get("args", ""),
            "start_time": scanner.get("start", ""),
            "version": scanner.get("version", ""),
        }

        # Parse hosts
        for host_elem in root.findall("host"):
            host = self._parse_host(host_elem)
            if host:
                result["hosts"].append(host)

        # Run stats
        runstats = root.find("runstats")
        if runstats is not None:
            finished = runstats.find("finished")
            hosts_stat = runstats.find("hosts")
            if finished is not None:
                result["stats"]["elapsed"] = finished.get("elapsed", "")
                result["stats"]["summary"] = finished.get("summary", "")
            if hosts_stat is not None:
                result["stats"]["hosts_up"] = int(hosts_stat.get("up", 0))
                result["stats"]["hosts_down"] = int(hosts_stat.get("down", 0))
                result["stats"]["hosts_total"] = int(hosts_stat.get("total", 0))

        return result

    def _parse_host(self, host_elem: ET.Element) -> dict[str, Any] | None:
        """Parse a single host element."""
        host: dict[str, Any] = {
            "status": "unknown",
            "addresses": {},
            "hostnames": [],
            "ports": [],
            "os": {},
        }

        # Status
        status = host_elem.find("status")
        if status is not None:
            host["status"] = status.get("state", "unknown")

        # Addresses
        for addr in host_elem.findall("address"):
            addr_type = addr.get("addrtype", "")
            host["addresses"][addr_type] = addr.get("addr", "")
            if addr_type == "mac":
                host["addresses"]["vendor"] = addr.get("vendor", "")

        # Hostnames
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            for hn in hostnames.findall("hostname"):
                host["hostnames"].append({
                    "name": hn.get("name", ""),
                    "type": hn.get("type", ""),
                })

        # Ports
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_info: dict[str, Any] = {
                    "port": int(port.get("portid", 0)),
                    "protocol": port.get("protocol", "tcp"),
                }
                state = port.find("state")
                if state is not None:
                    port_info["state"] = state.get("state", "")
                service = port.find("service")
                if service is not None:
                    port_info["service"] = service.get("name", "")
                    port_info["product"] = service.get("product", "")
                    port_info["version"] = service.get("version", "")
                    port_info["extrainfo"] = service.get("extrainfo", "")
                host["ports"].append(port_info)

        # OS detection
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                host["os"] = {
                    "name": osmatch.get("name", ""),
                    "accuracy": osmatch.get("accuracy", ""),
                }

        return host
