#include "server.h"
#include <future>
#include <sstream>
#include <stdexcept>
#include <signal.h>

namespace httppp {
    static std::vector<Server*> servers;

    static void signalHandler(int signum) {
        switch(signum) {
            case SIGINT:
            case SIGKILL:
                for(auto server : servers) {
                    if(server)
                        server->stop();
                }
                break;
            case SIGPIPE:
                printf("Broken pipe\n");
                break;
            default:
                break;
        }
    }

    Server::Server() {
        isRunning.store(false);
        configuration.loadDefault();
    }

    Server::Server(const Configuration &configuration) {
        this->configuration = configuration;
        isRunning.store(false);
    }

    Server::Server(const Server &other) {
        configuration = other.configuration;
        listeners = other.listeners;
        sslContext = other.sslContext;
        isRunning.store(other.isRunning);
    }

    Server::Server(Server &&other) noexcept {
        configuration = std::move(other.configuration);
        listeners = std::move(other.listeners);
        sslContext = std::move(other.sslContext);
        isRunning.store(other.isRunning);
        listenThread = std::move(other.listenThread);
    }
    
    Server& Server::operator=(const Server &other) {
        if(this != &other) {
            configuration = other.configuration;
            listeners = other.listeners;
            sslContext = other.sslContext;
            isRunning.store(other.isRunning);
        }
        return *this;
    }

    Server& Server::operator=(Server &&other) noexcept {
        if(this != &other) {
            configuration = std::move(other.configuration);
            listeners = std::move(other.listeners);
            sslContext = std::move(other.sslContext);
            isRunning.store(other.isRunning);
            listenThread = std::move(other.listenThread);
        }
        return *this;
    }
    
    void Server::start() {
        if(isRunning.load() || listenThread.joinable())
            return;

        registerSignals();

        isRunning.store(true);

        listenThread = std::thread(&Server::listen, this);
        listenThread.join();
        
        unregisterSignals();
    }

    void Server::stop() {
        isRunning.store(false);        
    }

    void Server::listen() {
        try {
            sslContext = SslContext(configuration.certificatePath, configuration.privateKeyPath);
        } catch (const SslException &ex) {
            printf("Failed to initialize SslContext: %s\n", ex.what());
            isRunning.store(false);
            return;
        }

        SocketOption options = SocketOption_Reuse | SocketOption_NonBlocking;
        listeners.emplace_back(configuration.bindAddress, configuration.port, 10, options);
        listeners.emplace_back(configuration.bindAddress, configuration.portSSL, 10, options);

        for(size_t i = 0; i < listeners.size(); i++) {
            if(!listeners[i].start()) {
                printf("Failed to start listening on port %zu\n", listeners[i].getPort());
                isRunning.store(false);
                goto cleanup;
            }
        }

        printf("Server listening on http://%s:%zu\n", configuration.hostName.c_str(), configuration.port);
        printf("Server listening on https://%s:%zu\n", configuration.hostName.c_str(), configuration.portSSL);

        while(isRunning.load()) {
            for(size_t i = 0; i < listeners.size(); i++) {
                Socket client;

                if(listeners[i].accept(client)) {
                    if(listeners[i].getPort() == configuration.portSSL) {
                        try {
                            SslStream sslStream(client, sslContext);
                            NetworkStream connection(client, sslStream);
                            std::async(std::launch::async, &Server::handleClient, this, std::move(connection));
                        } catch (const SslException &ex) {
                            client.close();
                        }
                    } else {
                        NetworkStream connection(client);
                        std::async(std::launch::async, &Server::handleClient, this, std::move(connection));
                    }
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

    cleanup:
        for(size_t i = 0; i < listeners.size(); i++) {
            listeners[i].close();
        }

        sslContext.dispose();
    }

    void Server::handleClient(NetworkStream connection) {
        std::string header;

        if(readHeader(connection, header) != HeaderError::None) {                    
            sendBadRequest(connection);
            return;
        }

        HttpRequest request;

        try {
            request.method = readMethod(header);
        } catch (const std::invalid_argument& e) {
            sendBadRequest(connection);
            return;
        }

        try {
            request.path = readPath(header);
        } catch (const std::invalid_argument& e) {
            sendBadRequest(connection);
            return;
        }
        
        request.headers = readHeaderFields(header);

        std::string m = request.getMethodString();
        printf("[%s] %s\n", m.c_str(), request.path.c_str());

        if(!connection.isSecure()) {
            redirectToHttps(connection, request);
            return;
        }

        if(onRequest) {
            onRequest(connection, request);
        } else {
            sendOk(connection);
        }
    }

    HeaderError Server::readHeader(NetworkStream &socket, std::string &header) {
        const std::string endOfHeader = "\r\n\r\n";
        constexpr size_t BUFFER_SIZE = 1024;        
        char buffer[BUFFER_SIZE]; // Buffer to hold peeked data
        memset(buffer, 0, BUFFER_SIZE);

        size_t endOfHeaderLength = endOfHeader.length();
        size_t totalBytesRead = 0;

        while (true) {
            // Peek into the socket
            ssize_t bytesPeeked = socket.peek(buffer, BUFFER_SIZE);
            if (bytesPeeked <= 0) {
                printf("HeaderError::FailedToPeek\n");
                return HeaderError::FailedToPeek;
            }

            // Convert peeked data to string for easier processing
            std::string peekedData(buffer, bytesPeeked);
            header.append(peekedData);
            totalBytesRead += bytesPeeked;

            // Check if the end of the header has been reached
            if (header.length() >= endOfHeaderLength && 
                header.compare(header.length() - endOfHeaderLength, endOfHeaderLength, endOfHeader) == 0) {
                break; // End of header found
            }
        }

        // Now read the header from the socket
        std::string completeHeader;
        completeHeader.resize(totalBytesRead);
        ssize_t bytesRead = socket.read(&completeHeader[0], totalBytesRead);
        if (bytesRead <= 0) {
            // Handle error or end of stream
            printf("HeaderError::FailedToRead\n");
            return HeaderError::FailedToRead;
        }
        if(totalBytesRead > configuration.maxHeaderSize) {
            printf("HeaderError::MaxSizeExceeded\n");
            return HeaderError::MaxSizeExceeded;
        }

        return HeaderError::None; // Return the complete HTTP header
    }

    HttpMethod Server::readMethod(const std::string &header) {
        std::istringstream stream(header);
        std::string method;

        // Read the first word from the header
        if (stream >> method) {
            if (method == "GET") {
                return HttpMethod::GET;
            } else if (method == "POST") {
                return HttpMethod::POST;
            } else if (method == "PUT") {
                return HttpMethod::PUT;
            } else if (method == "DELETE") {
                return HttpMethod::DELETE;
            } else if (method == "HEAD") {
                return HttpMethod::HEAD;
            } else if (method == "OPTIONS") {
                return HttpMethod::OPTIONS;
            } else if (method == "PATCH") {
                return HttpMethod::PATCH;
            } else if (method == "TRACE") {
                return HttpMethod::TRACE;
            } else if (method == "CONNECT") {
                return HttpMethod::CONNECT;
            } else {
                throw std::invalid_argument("Unknown HTTP method: " + method);
            }
        }

        throw std::invalid_argument("Invalid header format: " + header);
    }

    std::string Server::readPath(const std::string &header) {
        std::istringstream stream(header);
        std::string method;
        std::string path;

        // Read the first word (method)
        if (stream >> method) {
            // Read the second word (path)
            if (stream >> path) {
                return path; // Return the extracted path
            }
        }

        throw std::invalid_argument("Invalid header format: " + header);
    }

    Headers Server::readHeaderFields(const std::string &header) {
        auto headerLines = String::split(header, "\r\n");
        std::unordered_map<std::string,std::string> headers;

        for(size_t i = 0; i < headerLines.size(); i++) {
            auto headerParts = String::split(headerLines[i], ":");
            if(headerParts.size() != 2)
                continue;
            std::string key = String::trim(headerParts[0]);
            std::string value = String::trim(headerParts[1]);
            headers[key] = value;
        }
        return headers;
    }

    void Server::sendOk(NetworkStream client) {
        std::string response = "HTTP/1.1 200 OK\r\n\r\n";
        client.write(response.c_str(), response.size());
        client.close();
    }

    void Server::sendBadRequest(NetworkStream client) {
        std::string response = "HTTP/1.1 400\r\n\r\n";
        client.write(response.c_str(), response.size());
        client.close();
    }

    void Server::redirectToHttps(NetworkStream client, const HttpRequest &request) {
        std::string location = "https://" + configuration.hostName + 
                                ":" + std::to_string(configuration.portSSL) + 
                                request.path;
        HttpResponse response(301);
        response.addHeader("Location", location);
        response.addHeader("Connection", "close");
        std::string responseText = response.getText();
        client.write(responseText.c_str(), responseText.size());
        client.close();
    }

    void Server::registerSignals() {
        for(size_t i = 0; i < servers.size(); i++) {
            if(servers[i] == this);
                return;
        }

        servers.push_back(this);
        signal(SIGINT, &signalHandler);
        signal(SIGKILL, &signalHandler);
        signal(SIGPIPE, &signalHandler);
    }

    void Server::unregisterSignals() {
        bool found = false;
        size_t index = 0;
        for(size_t i = 0; i < servers.size(); i++) {
            if(servers[i] == this) {
                found = true;
                index = i;
                break;
            }
        }

        if(found) {
            servers.erase(servers.begin() + index);
        }
    }
}