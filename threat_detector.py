def parse_log_line(line):
    parts = line.split()
    return {
        "timestamp": parts[0],
        "src_ip": parts[1],
        "dest_port": int(parts[2]),
        "action": parts[3]
    }

def is_suspicious(ip, blacklist):
    return ip in blacklist

# Данные (логи)
logs = [
    "10:00 5.5.5.5 80 blocked",
    "10:01 10.0.0.2 22 allowed",
    "10:02 5.5.5.5 443 blocked",
    "10:03 192.168.1.1 80 allowed",
    "10:04 5.5.5.5 22 blocked",
    "10:05 10.0.0.2 443 allowed",
    "10:06 5.5.5.5 80 blocked",
    "10:07 10.0.0.2 22 blocked",
    "10:08 192.168.1.1 443 blocked",
    "10:09 5.5.5.5 80 blocked"
]

blacklist = ["10.0.0.2", "5.5.5.5"]

threat_count = {}

for line in logs:
    parsed = parse_log_line(line)
    ip = parsed["src_ip"]
    if is_suspicious(ip, blacklist):
        print(f"🚨 ОБНАРУЖЕНА УГРОЗА: IP {ip} из черного списка!")
        if ip in threat_count:
            threat_count[ip] += 1
        else:
            threat_count[ip] = 1

print("Угрозы по IP:", threat_count)
