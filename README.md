# httppp
A simple http 1.1 server in C++. My goal was to stay away from making too many abstractions around http requests and responses. From previous attempts I've learnt that things become unwieldy very quick as I narrowed myself into a certain corner. As a result, this library gives more freedom on how to structure a server and how to deal with requests and responses. The server just gives you a `NetworkStream` and `HttpRequest` in a `onRequest` callback, and from there you decide how to handle it. Still however, this project is just for fun and educational purposes and I do not recommend using it in production.

# Requirements
- OpenSSL

# Notes
- In theory should work on windows, although not tested.

# Example
```cpp
#include "httppp.h"

using namespace httppp;

void onRequest(NetworkStream connection, HttpRequest &request) {
    if(request.method == HttpMethod::GET) {
        std::string content = "<h1>Hello world</h1>";
        content += "<p>You requested: " + request.path + "</p>";

        HttpResponse response(HttpStatusCode::OK);
        response.setHeader("Content-Length", std::to_string(content.size()));
        response.setHeader("Content-Type", "text/html");
        response.setHeader("Connection", "close");

        TextStream textStream(content);
        connection.write(connection, &textStream);
    } else {
        HttpResponse response(501); //501: Method not implemented
        std::string responseText = response.getText();
        connection.write(responseText.c_str(), responseText.size());
    }
    connection.close();
}

int main(int argc, char **argv) {
    Configuration configuration;
    configuration.bindAddress = "0.0.0.0";
    configuration.certificatePath = "cert.pem";
    configuration.privateKeyPath = "key.pem";
    configuration.hostName = "localhost";
    configuration.maxHeaderSize = 8192;
    configuration.port = 8080;
    configuration.portHttps = 8081;
    configuration.useHttps = true;
    configuration.useHttpsForwarding = true;

    Server server(configuration);
    server.onRequest = onRequest;
    server.start();

    return 0;
}
```
