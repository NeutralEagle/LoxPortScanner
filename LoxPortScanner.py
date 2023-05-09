import subprocess
import time
import socket
import concurrent.futures
import threading

ipGen2 = '10.121.4.180' #Versiontest GW - Gen2 MS
portsGen2 = [21, 80, 443] #22 open only on versiontest for debugging
portsGen2udp = []
ipGen1 = '10.121.4.181' #Versiontest client 1 - Gen1 MS
portsGen1 = [21, 80, 443]
portsGen1udp = []
ipCompact = '10.121.4.185' #Versiontest client 5 - Compact
portsCompact = [21, 80, 139, 443, 445, 7090] #22 open only on versiontest for debugging
portsCompactudp = []
timeout = 0.030 #Timeout for packets (30ms)

def app_check():
    file_path = r"C:\Users\Honza_Lox\Downloads\lxcommunicator-master\test\index.html"
    num_instances = 1
    
    chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    
    # Open the first instance in a window
    subprocess.Popen([chrome_path, "--new-window", file_path])
    time.sleep(1)
    # Open the remaining instances in new tabs
    for i in range(1, num_instances):
        subprocess.Popen([chrome_path, "--new-tab", file_path])
        time.sleep(1)

def scan_tcp_port(target_ip, port, lock):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((target_ip, port))
    if result == 0:
        with lock:
            print(f'--TCP port {port} is open')
        return port
    sock.close()


def scan_udp_port(target_ip, port, lock):
    # Check 1 - listen for udp answer
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.bind(('0.0.0.0', 0))
        sock.sendto(b'test', (target_ip, port))
        data, addr = sock.recvfrom(1024)
        with lock:
            print(f'--UDP port {port} is open')
        return port
    except socket.timeout:
        pass
    finally:
        sock.close()

    # Check 2 - send empty message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b'', (target_ip, port))
        data, addr = sock.recvfrom(1024)
        with lock:
            print(f'--UDP port {port} is open')
        return port
    except socket.timeout:
        pass
    finally:
        sock.close()

    # Check NBNS
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b'\x94\x7e\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01', (target_ip, port))
        data, addr = sock.recvfrom(1024)
        with lock:
            print(f'--UDP port {port} is open')
        return port
    except socket.timeout:
        pass
    finally:
        sock.close()
        
    # Check MDNS
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09\x5f\x73\x65\x72\x76\x69\x63\x65\x73\x07\x5f\x64\x6e\x73\x2d\x73\x64\x04\x5f\x75\x64\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0c\x00\x01', (target_ip, port))
        data, addr = sock.recvfrom(1024)
        with lock:
            print(f'--UDP port {port} is open')
        return port
    except socket.timeout:
        pass
    finally:
        sock.close()
     
    # Check 5 - Portmap
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
         sock.sendto(b'\x72\xfe\x1d\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x01\x97\x7c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', (target_ip, port))
         data, addr = sock.recvfrom(1024)
         with lock:
             print(f'--UDP port {port} is open')
         return port
    except socket.timeout:
         pass
    finally:
         sock.close()

def check_ports(target_ip, tcp_ports, udp_ports, compact):
    min_port = 1
    max_port = 65535
    allowedTCP_ports = tcp_ports.copy() + [22]
    allowedUDP_ports = udp_ports.copy() + [5353]
    if compact:
        allowedTCP_ports += [7091,7092,7093,7094,7095,7097] + list(range(10000, 65535))
        allowedUDP_ports += [137] + list(range(10000, 65535))
    open_tcp_ports = []
    open_udp_ports = []
    print("----------------------------------------------------\n")
    print(f"Checking open ports of {target_ip}")

    lock = threading.Lock()

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        # TCP port scanning
        print(f"Checking TCP ports {min_port} to {max_port}")
        print(f"Open ports should be: {tcp_ports}")
        futures_tcp = {executor.submit(scan_tcp_port, target_ip, port, lock): port for port in range(min_port, max_port)}
        for future in concurrent.futures.as_completed(futures_tcp):
            result = future.result()
            if result:
                open_tcp_ports.append(result)

        # UDP port scanning
        print(f"Checking UDP ports {min_port} to {max_port}")
        print(f"Open ports should be: {udp_ports}")
        futures_udp = {executor.submit(scan_udp_port, target_ip, port, lock): port for port in range(min_port, max_port)}
        for future in concurrent.futures.as_completed(futures_udp):
            result = future.result()
            if result:
                open_udp_ports.append(result)

    # Check if open ports match the expected lists of TCP and UDP ports
    matched_tcp_ports = list(set(open_tcp_ports) & set(tcp_ports))
    matched_udp_ports = list(set(open_udp_ports) & set(udp_ports))
    unexpected_tcp_ports = list(set(open_tcp_ports) - set(allowedTCP_ports))
    unexpected_udp_ports = list(set(open_udp_ports) - set(allowedUDP_ports))
    found_allowed_tcp_ports = list(set(allowedTCP_ports)-(set(allowedTCP_ports)-(set(open_tcp_ports)-set(tcp_ports))))
    found_allowed_udp_ports = list(set(allowedUDP_ports)-(set(allowedUDP_ports)-(set(open_udp_ports)-set(udp_ports))))

    tcp_ports.sort()
    udp_ports.sort()
    open_tcp_ports.sort()
    open_udp_ports.sort()
    matched_tcp_ports.sort()
    matched_udp_ports.sort()
    unexpected_tcp_ports.sort()
    unexpected_udp_ports.sort()
    open_tcp_ports
    # Print results
    print('Scanning complete.\n')
    print(f'Open TCP ports: {open_tcp_ports}')
    print(f'Open UDP ports: {open_udp_ports}')
    if len(matched_tcp_ports) > 0:
        print(f"Expected ports found{matched_tcp_ports}")
    if len(matched_udp_ports) > 0:
        print(f"Expected UDP ports found{matched_udp_ports}")
    if len(found_allowed_tcp_ports) > 0:
        print(f"Allowed TCP ports found {found_allowed_tcp_ports}")
    if len(found_allowed_udp_ports) > 0:
        print(f"Allowed UDP ports found {found_allowed_udp_ports}")

    if matched_tcp_ports == tcp_ports and matched_udp_ports == udp_ports and len(unexpected_tcp_ports) == 0 and len(unexpected_udp_ports) == 0:
        print('All expected ports are open\n')
        
        return True
    else:
        if len(unexpected_tcp_ports) > 0:
            print(f'Unexpected TCP port(s) found: {unexpected_tcp_ports}')
        if len(unexpected_udp_ports) > 0:
            print(f'Unexpected UDP port(s) found: {unexpected_udp_ports}')
        print('One or more expected ports are closed, or found unexpected ports!\n')
        return False
    
    
#app_check()

result1 = check_ports(ipGen2, portsGen2, portsGen2udp, False)
result2 = check_ports(ipGen1, portsGen1, portsGen1udp, False)
result3 = check_ports(ipCompact, portsCompact, portsCompactudp, True)

print(f'Result for Gen2 {ipGen2}: {result1}\n')
print(f'Result for Gen1 {ipGen1}: {result2}\n')
print(f'Result for Compact {ipCompact}: {result3}')
