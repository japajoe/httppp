#include "server.h"

using namespace httppp;

void onRequest(NetworkStream connection, const HttpRequest &request) {
    std::string content = "<h1>Hello world</h1>";
    content += "<p>You requested: " + request.path + "</p>";

    HttpResponse response(200);
    response.addHeader("Content-Length", std::to_string(content.size()));
    response.addHeader("Content-Type", "text/html");
    response.addHeader("Connection", "close");
    response.addContent(content);

    std::string responseText = response.getText();

    connection.write(responseText.c_str(), responseText.size());
    connection.close();
}

int main(int argc, char **argv) {
    Configuration configuration;
    configuration.loadDefault();

    Server server(configuration);
    server.onRequest = onRequest;
    server.start();

    return 0;
}