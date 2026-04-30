# ot_recon/core/classifier.py

def classify(data):
    for host in data:
        protocols = [p["protocol"] for p in host.get("ot_ports", [])]

        host["type"] = "Unknown"
        host["notes"] = ""

        if not protocols:
            continue

        # Basic logic (v1)
        if "S7" in protocols:
            host["type"] = "PLC"
            host["notes"] = "Siemens PLC likely"

        elif "Modbus" in protocols:
            host["type"] = "Field Device / PLC"
            host["notes"] = "Modbus device detected"

        elif "EtherNet/IP" in protocols:
            host["type"] = "PLC / Industrial Device"
            host["notes"] = "Rockwell ecosystem likely"

        elif "DNP3" in protocols:
            host["type"] = "SCADA / RTU"
            host["notes"] = "DNP3-based system"

        elif "OPC UA" in protocols:
            host["type"] = "Industrial Server"
            host["notes"] = "OPC UA server detected"

        elif "HTTP" in protocols and "VNC" in protocols:
            host["type"] = "HMI"
            host["notes"] = "Possible HMI panel (web + remote access)"

        elif "SSH" in protocols:
            host["notes"] += " | Remote admin access enabled"

        elif "FTP" in protocols:
            host["notes"] += " | File transfer service exposed"

        # Multi-protocol hint
        if len(protocols) > 1:
            host["notes"] += " | Multiple OT protocols detected"

    return data