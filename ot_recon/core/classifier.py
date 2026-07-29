def classify(data):

    for host in data:

        evidence = host.get("evidence", [])

        protocols = [
            p["protocol"]
            for p in host.get("ot_ports", [])
        ]

        #
        # Evidence-based classification
        #

        if any(
            "SIMATIC HMI" in e
            for e in evidence
        ):

            host["type"] = "HMI"
            host["confidence"] = "Very High"

        elif any(
            "Human-Machine Interface" in e
            for e in evidence
        ):

            host["type"] = "HMI"
            host["confidence"] = "Very High"

        elif any(
            "Module Type: PLC" in e
            for e in evidence
        ):

            host["type"] = "PLC"
            host["confidence"] = "Very High"

        elif any(
            "Programmable Logic Controller" in e
            for e in evidence
        ):

            host["type"] = "PLC"
            host["confidence"] = "Very High"

        #
        # Fallbacks
        #

        elif "Modbus" in protocols:

            host["type"] = "Field Device"
            host["confidence"] = "Medium"

        elif "S7" in protocols:

            host["type"] = "Possible PLC"
            host["confidence"] = "Medium"

        elif "EtherNet/IP" in protocols:

            host["type"] = "Possible PLC"
            host["confidence"] = "Medium"

        elif "OPC UA" in protocols:

            host["type"] = "Industrial Server"
            host["confidence"] = "Medium"

        else:

            host["type"] = "Unknown"
            host["confidence"] = "Low"

    return data