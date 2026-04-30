# core/enricher.py

import yaml

def load_port_map():
    with open("data/ports.yaml", "r") as f:
        return yaml.safe_load(f)


def enrich(data):
    port_map = load_port_map()

    for host in data:
        enriched_ports = []

        for p in host["ports"]:
            port = str(p["port"])
            state = p["state"]

            if port in port_map:
                enriched_ports.append({
                    "port": p["port"],
                    "state": state,
                    "protocol": port_map[port]["protocol"],
                    "desc": port_map[port]["desc"]
                })

        host["ot_ports"] = enriched_ports

    return data