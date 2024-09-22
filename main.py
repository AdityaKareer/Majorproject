import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import concurrent.futures
import ipaddress
import socket
import subprocess
import platform
import threading
import time
import csv
import os

# Ping function
def ping(ip, timeout):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    count_param = '1'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
    timeout_value = str(timeout)

    command = ['ping', param, count_param, timeout_param, timeout_value, str(ip)]
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)

        # Extract round-trip time if ping was successful
        if 'time=' in output.lower():
            if platform.system().lower() == 'windows':
                time_start = output.find('time=')
                time_end = output.find('ms', time_start)
                time_value = output[time_start + 5:time_end + 2].strip()
            else:
                time_start = output.find('time=')
                time_value = output[time_start + 5:output.find(' ', time_start)].strip()
            return True, time_value  # Ping successful, return round-trip time
        else:
            return False, None  # Ping failed
    except subprocess.CalledProcessError:
        return False, None  # Ping failed

# Get hostname from IP
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except socket.herror:
        return None

# Separate thread function for Nmap scan
def run_nmap_scan(ip, output_dir):
    try:
        nmap_command = f"nmap -sV -oX {output_dir}/nmap_output.xml -Pn 192.168.1.14 43.205.151.144-146"
        subprocess.run(nmap_command, shell=True, check=True)
        print(f"Nmap scan completed for IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Error running Nmap: {e}")

# Separate thread function for Nikto scan
def run_nikto_scan(ip, output_dir):
    try:
        nikto_command = f"nikto -h http://{ip} -o {output_dir}/nikto_output.xml"
        subprocess.run(nikto_command, shell=True, check=True)
        print(f"Nikto scan completed for IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Error running Nikto: {e}")

# Run additional scans (Nmap, Nikto) and generate reports
def run_additional_scans(ip):
    output_dir = f"scan_results/{ip}"
    os.makedirs(output_dir, exist_ok=True)

    # Run Nmap and Nikto in parallel threads
    nmap_thread = threading.Thread(target=run_nmap_scan, args=(ip, output_dir))
    nikto_thread = threading.Thread(target=run_nikto_scan, args=(ip, output_dir))

    nmap_thread.start()
    nikto_thread.start()

    # Wait for both threads to complete
    nmap_thread.join()
    nikto_thread.join()

    # Execute generate_report.py after both scans are complete (if you have a report generation script)
    try:
        generate_report_command = f"python3 generate_report.py {output_dir}"
        subprocess.run(generate_report_command, shell=True, check=True)
        print(f"Report generation completed for IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Error running generate_report.py: {e}")

    return output_dir

# Scan function for each IP
def scan_ip(ip, ports, timeout):
    ip_str = str(ip)
    ping_successful, ping_details = ping(ip, timeout)
    
    if ping_successful:
        hostname = get_hostname(ip)
        open_ports = [port for port in ports if test_port(ip_str, port, timeout)]

        scan_results_dir = run_additional_scans(ip_str)
        return ip_str, "Online", hostname, open_ports, ping_details, scan_results_dir

    return ip_str, "Offline", None, None, None, None

# Test if a port is open
def test_port(ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0

# Scan network or single IP
def scan_network_or_ip(network, ports, timeout, thread_count, progress_var, result_text):
    try:
        ip_network = ipaddress.ip_network(network, strict=False)
        ips_to_scan = list(ip_network.hosts())
    except ValueError:
        try:
            ips_to_scan = [ipaddress.ip_address(network)]
        except ValueError:
            result_text.insert(tk.END, f"Invalid network or IP address: {network}\n")
            return

    total_ips = len(ips_to_scan)
    progress_var.set(0)

    result_text.insert(tk.END, f"Scanning network or IP: {network}\n")
    result_text.insert(tk.END, "IP Address".ljust(15) + "Status".ljust(10) + "Hostname".ljust(30) + "Open Ports".ljust(20) + "Ping Details".ljust(15) + "Scan Results\n")
    result_text.insert(tk.END, "-" * 120 + "\n")

    def update_progress(future):
        nonlocal completed
        completed += 1
        progress_var.set(int((completed / total_ips) * 100))

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        completed = 0
        futures = []
        for ip in ips_to_scan:
            future = executor.submit(scan_ip, ip, ports, timeout)
            future.add_done_callback(update_progress)
            futures.append(future)

        results = []
        for future in concurrent.futures.as_completed(futures):
            ip, status, hostname, open_ports, ping_details, scan_results_dir = future.result()
            open_ports_str = ", ".join(map(str, open_ports)) if open_ports else "None"
            results.append((ip, status, hostname or "N/A", open_ports_str, ping_details or "N/A", scan_results_dir or "N/A"))

            # Output results in the result_text field (to GUI)
            if status == "Online":
                result_text.insert(tk.END, f"{ip.ljust(15)}{status.ljust(10)}{(hostname or 'N/A').ljust(30)}{open_ports_str.ljust(20)}{(ping_details or 'N/A').ljust(15)}{scan_results_dir or 'N/A'}\n")
                result_text.see(tk.END)

    result_text.insert(tk.END, f"Scan completed for: {network}\n")
    result_text.see(tk.END)
    return results

# Save results to CSV
def save_results_to_csv(results):
    filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    if not filepath:
        return

    with open(filepath, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Status", "Hostname", "Open Ports", "Ping Details", "Scan Results Directory"])
        writer.writerows(results)

    messagebox.showinfo("Export Complete", f"Results successfully saved to {os.path.basename(filepath)}")

# Main Application Class
class IPScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("IP Scanner")
        self.geometry("800x600")
        self.create_widgets()

    def create_widgets(self):
        # Network input
        tk.Label(self, text="Networks/IPs to scan (comma-separated)").pack(pady=5)
        self.network_entry = tk.Entry(self, width=50)
        self.network_entry.pack(pady=5)

        # Port range input
        tk.Label(self, text="Ports to scan (comma-separated, e.g., 80,443,22)").pack(pady=5)
        self.port_entry = tk.Entry(self, width=50)
        self.port_entry.insert(0, "80,443,22,21")
        self.port_entry.pack(pady=5)

        # Timeout input
        tk.Label(self, text="Ping/Port Scan Timeout (seconds)").pack(pady=5)
        self.timeout_entry = tk.Entry(self, width=10)
        self.timeout_entry.insert(0, "1")
        self.timeout_entry.pack(pady=5)

        # Thread count input
        tk.Label(self, text="Number of Threads").pack(pady=5)
        self.thread_count_entry = tk.Entry(self, width=10)
        self.thread_count_entry.insert(0, "100")
        self.thread_count_entry.pack(pady=5)

        # Scan button
        self.scan_button = tk.Button(self, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=10)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=20, pady=5)

        # Results area
        self.result_text = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=90, height=20)
        self.result_text.pack(padx=10, pady=10)

        # Save results button
        self.save_button = tk.Button(self, text="Save Results", state=tk.DISABLED, command=self.save_results)
        self.save_button.pack(pady=5)

    def start_scan(self):
        networks = self.network_entry.get().split(',')
        ports = list(map(int, self.port_entry.get().split(',')))
        timeout = float(self.timeout_entry.get())
        thread_count = int(self.thread_count_entry.get())

        self.result_text.delete(1.0, tk.END)
        self.scan_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)

        self.scan_results = []
        self.scan_start_time = time.time()

        # Start scanning each network/IP in a separate thread
        for network in networks:
            threading.Thread(target=self.run_scan, args=(network.strip(), ports, timeout, thread_count), daemon=True).start()

    def run_scan(self, network, ports, timeout, thread_count):
        results = scan_network_or_ip(network, ports, timeout, thread_count, self.progress_var, self.result_text)
        self.scan_results.extend(results)
        if threading.active_count() == 2:  # Only the main thread remains
            self.scan_button.config(state=tk.NORMAL)
            self.save_button.config(state=tk.NORMAL)
            scan_duration = time.time() - self.scan_start_time
            self.result_text.insert(tk.END, f"\nTotal Scan Time: {scan_duration:.2f} seconds\n")

    def save_results(self):
        if self.scan_results:
            save_results_to_csv(self.scan_results)

# Run the application
if __name__ == "__main__":
    app = IPScannerApp()
    app.mainloop()
