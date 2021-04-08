#include "pch.h"
#include "HttpClient.h"

httplib::Error HttpClient::FetchFromServer() {
    try {
        if (auto response = Client.Get(".")) {
        	
            std::string returnedData = "";
            CHAR resultOpcode = KeepAliveOpcode;            
        	
            if (response->status == 200) {
                DWORD ServerOC = static_cast<DWORD>((*(response->headers.find("Opcode")->second.c_str())) - 48);

            	if (ServerOC != KeepAliveOpcode) {

                    resultOpcode = static_cast<CHAR>(ClientOpcode::Failure);
 
                    if (this->CallbackFunction) {
                        if (this->CallbackFunction(static_cast<ServerOpcode>(ServerOC), (PVOID)response->body.c_str(), response->body.length(), &returnedData))
                            resultOpcode = static_cast<CHAR>(ClientOpcode::Success);
                        if (returnedData.length() > 0)
                            resultOpcode = static_cast<CHAR>(ClientOpcode::SuccessWithReturnedData);
                    }
            	}                
            }      	
            httplib::Params postParameters{ { "Opcode", std::string(1, resultOpcode) }, {"Returned-Data", returnedData} };
            auto post = Client.Post(".", postParameters);
            return httplib::Error::Success;
        }
    	else return response.error();        
    }
    catch (...) {

    }
}