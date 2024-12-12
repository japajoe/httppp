#ifndef HTTPPP_SERVER_HPP
#define HTTPPP_SERVER_HPP

#include "httppp.h"
#include <atomic>
#include <thread>
#include <functional>
#include <unordered_map>

namespace httppp {
    enum class HeaderError {
        None,
        FailedToPeek,
        FailedToRead,
        MaxSizeExceeded
    };

    enum class HttpMethod {
        GET,
        POST,
        PUT,
        DELETE,
        HEAD,
        OPTIONS,
        PATCH,
        TRACE,
        CONNECT
    };

    using Headers = std::unordered_map<std::string,std::string>;

    struct HttpRequest {
        HttpMethod method;
        std::string path;
        Headers headers;
        std::string getMethodString() const {
            switch(method) {
                case HttpMethod::GET:
                    return "GET";
                case HttpMethod::POST:
                    return "POST";
                case HttpMethod::PUT:
                    return "PUT";
                case HttpMethod::DELETE:
                    return "DELETE";
                case HttpMethod::HEAD:
                    return "HEAD";
                case HttpMethod::OPTIONS:
                    return "OPTIONS";
                case HttpMethod::PATCH:
                    return "PATCH";
                case HttpMethod::TRACE:
                    return "TRACE";
                case HttpMethod::CONNECT:
                    return "CONNECT";
            }
            return "UNSUPPORTED";
        }
    };

    struct HttpResponse {
        int responseCode;
        std::string header;
        std::string content;
        HttpResponse(int responseCode) {
            this->responseCode = responseCode;
        }
        void addHeader(const std::string &key, const std::string &value) {
            header += key + ": " + value + "\r\n";
        }
        void addContent(const std::string &s) {
            content = s;
        }
        std::string getText() const {
            if(content.size() > 0) {
                return "HTTP/1.1 " + std::to_string(responseCode) + "\r\n" + header + "\r\n" + content;
            } else {
                return "HTTP/1.1 " + std::to_string(responseCode) + "\r\n" + header + "\r\n";
            }
        }
    };

    struct Configuration {
        uint16_t port;
        uint16_t portSSL;
        uint32_t maxHeaderSize;
        std::string bindAddress;
        std::string certificatePath;
        std::string privateKeyPath;
        std::string hostName;

        void loadDefault() {
            port = 8080;
            portSSL = 8081;
            maxHeaderSize = 8192;
            bindAddress = "0.0.0.0";
            certificatePath = "cert.pem";
            privateKeyPath = "key.pem";
            hostName = "localhost";
        }
    };

    using RequestHandler = std::function<void(NetworkStream connection, const HttpRequest &request)>;

    class Server {
    public:
        RequestHandler onRequest;
        Server();
        Server(const Configuration &configuration);
        Server(const Server &other);
        Server(Server &&other) noexcept;
        Server& operator=(const Server &other);
        Server& operator=(Server &&other) noexcept;
        void start();
        void stop();
    private:
        Configuration configuration;
        std::vector<TcpListener> listeners;
        SslContext sslContext;
        std::atomic<bool> isRunning;
        std::thread listenThread;
        void listen();
        void handleClient(NetworkStream connection);
        HeaderError readHeader(NetworkStream &socket, std::string &header);
        HttpMethod readMethod(const std::string &header);
        std::string readPath(const std::string &header);
        Headers readHeaderFields(const std::string &header);
        void sendOk(NetworkStream client);
        void sendBadRequest(NetworkStream client);
        void redirectToHttps(NetworkStream client, const HttpRequest &request);
        void registerSignals();
        void unregisterSignals();
    };
}

#endif