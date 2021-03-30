#pragma once


#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "nlohmann/json.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

#include <Windows.h>

namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http = beast::http;       // from <boost/beast/http.hpp>
namespace net = boost::asio;        // from <boost/asio.hpp>
using tcp = net::ip::tcp;           // from <boost/asio/ip/tcp.hpp>
using Json = nlohmann::json;

class HttpRequest
{
public:

	/*
		Send HTTP request using the given parameters over socket communication.
		@return Json object represent the response data from the server.
	 */
	static Json sendRequest(const std::string& userAgent, int version, const std::string& contentType, const std::string& authorization,
		const http::verb& requestMethod, const std::string& hostname, const std::string& target, const std::string& port,
		const Json& payload);
};