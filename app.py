from flask import Flask, render_template, request
import nmap
import logging  # Import logging module

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='scanner.log', level=logging.DEBUG)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target_ip']
    ports = request.form.get('ports', '1-1024')
    scan_type = request.form.get('scan_type', '-sS')

    scanner = nmap.PortScanner()
    try:
        logging.info(f"Scanning target: {target} with ports: {ports} and scan type: {scan_type}")
        scanner.scan(target, ports, scan_type)

        scan_results = {}
        for host in scanner.all_hosts():
            scan_results['host'] = host
            scan_results['hostname'] = scanner[host].hostname()
            scan_results['state'] = scanner[host].state()
            scan_results['protocols'] = {}
            for proto in scanner[host].all_protocols():
                scan_results['protocols'][proto] = list(scanner[host][proto].keys())

        # Save results to a file
        with open('scan_results.txt', 'w') as file:
            file.write(f"Scan results for: {target}\n")
            file.write(f"Host: {scan_results.get('host')}\n")
            file.write(f"Hostname: {scan_results.get('hostname')}\n")
            file.write(f"State: {scan_results.get('state')}\n")
            file.write("Protocols:\n")
            for proto, ports in scan_results.get('protocols', {}).items():
                file.write(f"  {proto}: {', '.join(map(str, ports))}\n")

        return render_template('results.html', scan_results=scan_results)
    except nmap.PortScannerError as e:
        logging.error(f"PortScannerError: {e}")
        return "PortScannerError: Unable to scan the target. Please check the IP address and try again."
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return f"An error occurred: {e}"

if __name__ == '__main__':
    app.run(debug=True)
