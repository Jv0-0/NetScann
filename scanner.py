import socket

# Here we ask the input for the host or IP addres to scan
print("Enter the Host or IP address to scan: ")
ip = input()

#Here we define the function to scan the ports, we use socket to create a connection and check if the port is open or not, we set a timeout of 1 second to avoid hanging on closed ports. The function returns True if the port is open and False if it is closed. We then loop through the first 100 ports and call the scan_port function for each port, printing out which ports are open. Finally, we close the socket connection.
def scan_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    
    ip_scan = s.connect_ex((ip, port))
    s.close()
    
    return ip_scan == 0

# We loop through the ports that we want to scan and call the scan_port function for each port, printing out which ports are open.
for port in range(1, 101):
    if scan_port(ip, port):
        print(f"Port {port} is open.")
