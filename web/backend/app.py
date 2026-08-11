import os
import sys
import json
import uuid
import time
import shutil
import urllib.parse
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB_DIR = os.path.join(BASE_DIR, "web")
FRONTEND_DIR = os.path.join(WEB_DIR, "frontend")
UPLOADS_DIR = os.path.join(WEB_DIR, "uploads")
TEMP_DIR = os.path.join(WEB_DIR, "temp")

os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

def get_dpi_executable():
    candidates = [
        os.path.join(BASE_DIR, "build", "Release", "dpi_engine.exe"),
        os.path.join(BASE_DIR, "build", "dpi_engine.exe"),
        os.path.join(BASE_DIR, "build", "dpi_engine"),
        os.path.join(BASE_DIR, "build_direct", "dpi_engine.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None

REFERENCE_BENCHMARK = {
    "workload": "1,000,000 deterministic synthetic TCP packets",
    "parsers": 8,
    "fastpath_workers": 4,
    "throughput_pps": 651474,
    "bandwidth_mbps": 33.55,
    "speedup": 3.19,
    "packet_drops": 0,
    "validation_context": "Verified benchmark on GitHub Actions Ubuntu runner"
}

class DPIRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, code=200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _send_error_response(self, message, code=400):
        self._send_json({"status": "error", "message": message}, code=code)

    def _serve_file(self, file_path, content_type):
        if not os.path.isfile(file_path):
            self._send_error_response("File Not Found", 404)
            return
        with open(file_path, 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ['/', '/index.html']:
            self._serve_file(os.path.join(FRONTEND_DIR, 'index.html'), 'text/html; charset=utf-8')
        elif path == '/styles.css':
            self._serve_file(os.path.join(FRONTEND_DIR, 'styles.css'), 'text/css; charset=utf-8')
        elif path == '/app.js':
            self._serve_file(os.path.join(FRONTEND_DIR, 'app.js'), 'application/javascript; charset=utf-8')
        elif path == '/api/status':
            exe = get_dpi_executable()
            self._send_json({
                "status": "ready" if exe else "no_binary",
                "engine_binary": exe if exe else "Not found. Please build using 'cmake --build build --config Release'",
                "reference_benchmark": REFERENCE_BENCHMARK
            })
        elif path == '/api/samples':
            samples = []
            sample_candidates = ["test_dpi.pcap"]
            for s in sample_candidates:
                full_p = os.path.join(BASE_DIR, s)
                if os.path.isfile(full_p):
                    samples.append({
                        "filename": s,
                        "size_bytes": os.path.getsize(full_p)
                    })
            self._send_json({"samples": samples})
        else:
            self._send_error_response("Endpoint not found", 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path not in ['/api/analyze', '/api/synthetic']:
            self._send_error_response("Endpoint not found", 404)
            return

        content_length = int(self.headers.get('Content-Length', 0))
        body_bytes = self.rfile.read(content_length)

        exe = get_dpi_executable()
        if not exe:
            self._send_error_response("C++ DPI Engine executable not found. Please build the C++ project first: cmake --build build --config Release", 500)
            return

        run_id = str(uuid.uuid4())[:8]
        input_pcap = os.path.join(UPLOADS_DIR, f"input_{run_id}.pcap")
        output_pcap = os.path.join(TEMP_DIR, f"output_{run_id}.pcap")
        json_report = os.path.join(TEMP_DIR, f"report_{run_id}.json")

        block_apps = []
        block_domains = []
        block_ips = []
        num_parsers = 4

        try:
            if path == '/api/synthetic':
                req_data = json.loads(body_bytes.decode('utf-8')) if body_bytes else {}
                block_apps = req_data.get('block_apps', [])
                block_domains = req_data.get('block_domains', [])
                block_ips = req_data.get('block_ips', [])
                num_parsers = req_data.get('parsers', 4)

                sample_pcap = os.path.join(BASE_DIR, "test_dpi.pcap")
                if os.path.isfile(sample_pcap):
                    shutil.copyfile(sample_pcap, input_pcap)
                else:
                    self._send_error_response("Sample test_dpi.pcap not found in repository", 500)
                    return
            else:
                content_type = self.headers.get('Content-Type', '')
                if 'multipart/form-data' in content_type:
                    boundary = content_type.split("boundary=")[1].encode('utf-8')
                    parts = body_bytes.split(b'--' + boundary)
                    pcap_data = None

                    for part in parts:
                        if b'filename="' in part:
                            header, content = part.split(b'\r\n\r\n', 1)
                            pcap_data = content.rsplit(b'\r\n', 1)[0]
                        elif b'name="block_apps"' in part:
                            header, content = part.split(b'\r\n\r\n', 1)
                            val = content.rsplit(b'\r\n', 1)[0].decode('utf-8').strip()
                            if val: block_apps = [a.strip() for a in val.split(',') if a.strip()]
                        elif b'name="block_domains"' in part:
                            header, content = part.split(b'\r\n\r\n', 1)
                            val = content.rsplit(b'\r\n', 1)[0].decode('utf-8').strip()
                            if val: block_domains = [d.strip() for d in val.split(',') if d.strip()]
                        elif b'name="block_ips"' in part:
                            header, content = part.split(b'\r\n\r\n', 1)
                            val = content.rsplit(b'\r\n', 1)[0].decode('utf-8').strip()
                            if val: block_ips = [ip.strip() for ip in val.split(',') if ip.strip()]
                        elif b'name="sample_filename"' in part:
                            header, content = part.split(b'\r\n\r\n', 1)
                            sample_fn = content.rsplit(b'\r\n', 1)[0].decode('utf-8').strip()
                            if sample_fn:
                                sample_path = os.path.join(BASE_DIR, os.path.basename(sample_fn))
                                if os.path.isfile(sample_path):
                                    shutil.copyfile(sample_path, input_pcap)

                    if pcap_data and not os.path.exists(input_pcap):
                        with open(input_pcap, 'wb') as f:
                            f.write(pcap_data)
                elif 'application/json' in content_type:
                    req_data = json.loads(body_bytes.decode('utf-8'))
                    sample_fn = req_data.get('sample_filename', 'test_dpi.pcap')
                    block_apps = req_data.get('block_apps', [])
                    block_domains = req_data.get('block_domains', [])
                    block_ips = req_data.get('block_ips', [])
                    sample_path = os.path.join(BASE_DIR, os.path.basename(sample_fn))
                    if os.path.isfile(sample_path):
                        shutil.copyfile(sample_path, input_pcap)
                    else:
                        self._send_error_response(f"Sample file {sample_fn} not found", 400)
                        return

            if not os.path.isfile(input_pcap):
                self._send_error_response("No valid PCAP provided for analysis", 400)
                return

            cmd = [exe, input_pcap, output_pcap, "--json", json_report, "-p", str(num_parsers)]
            for app in block_apps:
                cmd.extend(["--block-app", app])
            for dom in block_domains:
                cmd.extend(["--block-domain", dom])
            for ip in block_ips:
                cmd.extend(["--block-ip", ip])

            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
            if res.returncode != 0:
                self._send_error_response(f"C++ DPI Engine execution failed: {res.stderr}", 500)
                return

            if not os.path.isfile(json_report):
                self._send_error_response("C++ DPI Engine did not produce JSON report", 500)
                return

            with open(json_report, 'r', encoding='utf-8') as jf:
                report_data = json.load(jf)

            report_data['reference_benchmark'] = REFERENCE_BENCHMARK
            report_data['execution'] = {
                "input_file": os.path.basename(input_pcap),
                "block_apps": block_apps,
                "block_domains": block_domains,
                "block_ips": block_ips
            }

            self._send_json(report_data)

        except Exception as e:
            self._send_error_response(f"Analysis error: {str(e)}", 500)
        finally:
            if os.path.exists(input_pcap):
                try: os.remove(input_pcap)
                except: pass
            if os.path.exists(output_pcap):
                try: os.remove(output_pcap)
                except: pass
            if os.path.exists(json_report):
                try: os.remove(json_report)
                except: pass

def run_server(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, DPIRequestHandler)
    print("=" * 60)
    print("  HIGH-PERFORMANCE DPI ENGINE — LOCAL WEB DASHBOARD")
    print("=" * 60)
    print(f"  Status: Server running locally on http://localhost:{port}")
    print(f"  Backend: Python http.server (Thin API Adapter)")
    print(f"  Core Engine: C++17 DPI Engine Binary")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping DPI Dashboard Server...")
        httpd.server_close()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run_server(port)
