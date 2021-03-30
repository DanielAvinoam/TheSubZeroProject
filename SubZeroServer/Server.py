from http.server import BaseHTTPRequestHandler, HTTPServer
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import os
import queue
import cgi

# General constants
PORT = 1230
WATCHED_PATH = "C:\\Users\\danie\\Desktop\\New folder (2)\\"

# Queue deceleration and constants
q = queue.Queue()
OPCODE = 0
FILE_PATH = 1

# Opcodes constant values
KEEP_ALIVE = 0


class ServerOpcode:
    InjectKernelShellcode, LoadLibraryReflectively, *_ = range(1, 10)


class ClientOpcode:
    Success, SuccessWithReturnedData, Failure, *_ = range(1, 10)


def OnFileCreation(event):
    if os.path.isdir(event.src_path):
        return

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
    #protocol_version = 'HTTP/1.1'

    def do_GET(self):
        #print("GET recieved")

        server_opcode = KEEP_ALIVE
        packet_body = b""

        if not q.empty():
            item = q.get()
            q.task_done()

            server_opcode = item[OPCODE]

            with open(item[FILE_PATH], 'rb') as file:
                packet_body = file.read()  # Read the file and send the contents

        self.send_response(200)
        #self.send_header("Connection", "keep-alive")
        self.send_header("Opcode", server_opcode)
        self.end_headers()

        self.wfile.write(packet_body)  # Read the file and send the contents



    def ParseClientHTTPRequest(self):
        client_opcode = int(self.headers.getheader('Opcode'))

        # USE match STATEMENT ON PYTHON 3.10 - CURRENTLY ON BETA
        if client_opcode == ClientOpcode.Success:
            print("[CLIENT] Operation completed successfully")
        elif client_opcode == ClientOpcode.SuccessWithReturnedData:
            print("[CLIENT] Operation completed successfully")
        else:
            print("[CLIENT] Operation failed")


    def do_POST(self):
        print("Post recieved")
        self.query_string = self.rfile.read(int(self.headers['Content-Length']))
        self.args = dict(cgi.parse_qsl(self.query_string))
        print(self.args)


if __name__ == "__main__":

    observer = DirectoryWatchdogSetup()
    observer.start()

    for filename in os.listdir(WATCHED_PATH):
        server_opcode = ServerOpcode.LoadLibraryReflectively if filename.endswith(".dll") else ServerOpcode.InjectKernelShellcode
        q.put((server_opcode, WATCHED_PATH + filename))

    Server = HTTPServer(("localhost", PORT), Handler)
    print("[SERVER] Server started...")
    try:
        Server.serve_forever()

    except KeyboardInterrupt:
        pass

    observer.stop()
    observer.join()

    Server.server_close()
    print("[SERVER] Server stopped.")
