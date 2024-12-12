#include "httppp.h"

using namespace httppp;

void onRequest(NetworkStream connection, HttpRequest &request) {
    if(request.method == HttpMethod::GET) {
        std::string content = "<h1>Hello world</h1>";
        content += "<p>You requested: " + request.path + "</p>";

        HttpResponse response(200);
        response.addHeader("Content-Length", std::to_string(content.size()));
        response.addHeader("Content-Type", "text/html");
        response.addHeader("Connection", "close");
        response.addContent(content);

        std::string responseText = response.getText();

        connection.write(responseText.c_str(), responseText.size());
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
    configuration.portSSL = 8081;

    Server server(configuration);
    server.onRequest = onRequest;
    server.start();

    return 0;
}