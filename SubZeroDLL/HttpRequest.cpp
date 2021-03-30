#include "pch.h"
#include "HttpRequest.h"


Json HttpRequest::sendRequest(const std::string& userAgent, int version, const std::string& contentType,
	const std::string& authorization, const http::verb& requestMethod, const std::string& hostname,
	const std::string& target, const std::string& port, const Json& payload)
{
	if (userAgent.empty() || hostname.empty() || target.empty())
	{
		throw std::runtime_error("Could not preform request if any of: hostname, user agent, target is missing");
	}

	if (version != 10 && version != 11)
	{
		throw std::runtime_error("Invalid HTTP version");
	}

	// The io_context is required for all I/O
	net::io_context ioc;

	// These objects perform our I/O
	tcp::resolver resolver(ioc);
	beast::tcp_stream stream(ioc);

	// Look up the domain name
	auto const results = resolver.resolve(hostname, port);

	// Make the connection on the IP address we get from a lookup
	stream.connect(results);

	// Set up an HTTP GET request message
	http::request<http::string_body> req{ requestMethod, target, version };
	req.set(http::field::host, hostname);
	req.set(http::field::user_agent, userAgent);

	if (!contentType.empty())
	{
		req.set(http::field::content_type, contentType);
	}

	if (!authorization.empty())
	{
		req.set(http::field::authorization, authorization);
	}

	const std::string requestPayload = payload.dump();
	if (!requestPayload.empty())
	{
		req.body() = requestPayload;
	}

	req.prepare_payload();
	//std::cout << req << std::endl;

	// Send the HTTP request to the remote host
	http::write(stream, req);

	// This buffer is used for reading and must be persisted
	beast::flat_buffer buffer;

	// Declare a container to hold the response
	http::response<http::dynamic_body> res;

	// Receive the HTTP response
	http::read(stream, buffer, res);

	// Print response:
	//std::cout << res << std::endl;
	std::string responseData = beast::buffers_to_string(res.body().data());
	Json jsResponseData = Json::parse(responseData);

	// Gracefully close the socket
	beast::error_code ec;
	stream.socket().shutdown(tcp::socket::shutdown_both, ec);

	// not_connected happens sometimes
	// so don't bother reporting it.
	//
	if (ec && ec != beast::errc::not_connected)
		throw beast::system_error{ ec };

	// If we get here then the connection is closed gracefully
	return jsResponseData;
}