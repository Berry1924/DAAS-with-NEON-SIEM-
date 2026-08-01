import socket


def heartbeat_payload(collector_id, version="1.0"):
    return {"collector_id": collector_id, "hostname": socket.gethostname(), "status": "ONLINE", "version": version}
