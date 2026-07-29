import subprocess
import re


def fingerprint(data):

    print("[+] Fingerprinting assets...")

    for host in data:

        host["evidence"] = []
        host["vendor"] = None
        host["model"] = None
        host["firmware"] = None

        ip = host["ip"]

        protocols = [
            p["protocol"]
            for p in host.get("ot_ports", [])
        ]

        #
        # Siemens Controller
        #
        if "S7" in protocols:

            try:

                result = subprocess.run(
                    [
                        "nmap",
                        "-n",
                        ip,
                        "-p", "102",
                        "-sV",
                        "--script", "s7-info"
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                output = result.stdout

                if "Siemens" in output:
                    host["vendor"] = "Siemens"

                module = re.search(r"Module:\s*(.+)", output)
                if module:
                    host["model"] = module.group(1).strip()

                version = re.search(r"Version:\s*(.+)", output)
                if version:
                    host["firmware"] = version.group(1).strip()

                if "Module Type: PLC" in output:
                    host["evidence"].append("Module Type: PLC")

                system_name = re.search(
                    r"System Name:\s*(.+)",
                    output
                )

                if system_name:
                    host["evidence"].append(
                        f"System Name: {system_name.group(1).strip()}"
                    )

            except Exception:
                pass

        #
        # Siemens Panel
        #
        if "HTTP" in protocols:

            try:

                result = subprocess.run(
                    [
                        "nmap",
                        "-n",
                        ip,
                        "-p", "80,443",
                        "-sV",
                        "--script",
                        "http-title,ssl-cert"
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                output = result.stdout

                if "SIMATIC HMI" in output:

                    host["vendor"] = "Siemens"

                    host["evidence"].append(
                        "SIMATIC HMI"
                    )

                title = re.search(
                    r"http-title:\s*(.+)",
                    output
                )

                if title:
                    host["evidence"].append(
                        f"Title: {title.group(1).strip()}"
                    )

            except Exception:
                pass

        #
        # Rockwell EtherNet/IP
        #
        if "EtherNet/IP" in protocols:

            try:

                result = subprocess.run(
                    [
                        "nmap",
                        "-n",
                        ip,
                        "-p", "44818",
                        "--script",
                        "enip-info"
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                output = result.stdout

                vendor = re.search(
                    r"vendor:\s*(.+)",
                    output
                )

                if vendor:
                    host["vendor"] = vendor.group(1).strip()

                product = re.search(
                    r"productName:\s*(.+)",
                    output
                )

                if product:
                    host["model"] = product.group(1).strip()

                revision = re.search(
                    r"revision:\s*(.+)",
                    output
                )

                if revision:
                    host["firmware"] = revision.group(1).strip()

                device_type = re.search(
                    r"type:\s*(.+)",
                    output
                )

                if device_type:

                    host["evidence"].append(
                        f"Device Type: {device_type.group(1).strip()}"
                    )

            except Exception:
                pass

    return data