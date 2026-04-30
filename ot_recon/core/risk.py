# ot_recon/core/risk.py

def assess_risk(data):
    for host in data:
        risks = []

        protocols = [p["protocol"] for p in host.get("ot_ports", [])]
        states = {p["protocol"]: p["state"] for p in host.get("ot_ports", [])}

        # 🔸 OT protocol risks
        if "Modbus" in protocols and states.get("Modbus") == "open":
            risks.append("Modbus exposed (no authentication)")

        if "S7" in protocols and states.get("S7") == "open":
            risks.append("Siemens S7 exposed")

        if "EtherNet/IP" in protocols and states.get("EtherNet/IP") == "open":
            risks.append("EtherNet/IP exposed")

        if "DNP3" in protocols and states.get("DNP3") == "open":
            risks.append("DNP3 exposed")

        if "OPC UA" in protocols and states.get("OPC UA") == "open":
            risks.append("OPC UA exposed (check security config)")

        # 🔸 IT/Access risks
        if "FTP" in protocols and states.get("FTP") == "open":
            risks.append("FTP open (insecure protocol)")

        if "VNC" in protocols and states.get("VNC") == "open":
            risks.append("VNC open (remote control risk)")

        if "HTTP" in protocols and states.get("HTTP") == "open":
            risks.append("HTTP open (unencrypted web interface)")

        if "SSH" in protocols and states.get("SSH") == "open":
            risks.append("SSH open (remote admin access)")

        # 🔸 Contextual risk
        if len(protocols) > 2:
            risks.append("Multiple services exposed (larger attack surface)")

        host["risks"] = risks

    return data