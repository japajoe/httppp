// MIT License

// Copyright (c) 2024 W.M.R Jap-A-Joe

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef HTTPPP_HPP
#define HTTPPP_HPP

#include <string>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <exception>
#include <sstream>
#include <type_traits>
#include <atomic>
#include <thread>
#include <functional>
#include <unordered_map>
#include <openssl/ssl.h>

#ifdef _WIN32
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0600
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h> // For fcntl
#endif

namespace httppp {
    typedef struct sockaddr_in sockaddr_in_t;
    typedef struct sockaddr_in6 sockaddr_in6_t;

    typedef union {
        sockaddr_in_t ipv4;
        sockaddr_in6_t ipv6;
    } socket_address_t;

    typedef struct {
        int32_t fd;
        socket_address_t address;
    } socket_t;

    enum class AddressFamily : int {
        AFInet = AF_INET,
        AFInet6 = AF_INET6
    };

    enum class IPVersion {
        IPv4,
        IPv6,
        Invalid
    };

    enum SocketOption_ {
        SocketOption_None = 0,
        SocketOption_Reuse = 1 << 0,
        SocketOption_NonBlocking = 1 << 1,
    };

    typedef int SocketOption;

    class Socket {
    public:
        Socket();
        Socket(AddressFamily addressFamily);
        Socket(const Socket &other);
        Socket(Socket &&other) noexcept;
        Socket& operator=(const Socket &other);
        Socket& operator=(Socket &&other) noexcept;
        void close();
        bool bind(const std::string &address, uint16_t port);
        bool connect(const std::string &ip, uint16_t port);
        bool listen(int32_t backlog);
        bool accept(Socket &socket);
        bool setOption(int level, int option, const void *value, uint32_t valueSize);
        void setNonBlocking();
        int32_t readByte();
        ssize_t read(void *buffer, size_t size);
        ssize_t write(const void *buffer, size_t size);
        ssize_t peek(void *buffer, size_t size);
        ssize_t receiveFrom(void *buffer, size_t size);
        ssize_t sendTo(const void *buffer, size_t size);
        int32_t getFileDescriptor() const;
        bool isSet() const;
        static IPVersion detectIPVersion(const std::string &ip);
    private:
        socket_t s;        
    };

    class TcpListener {
    public:
        TcpListener();
        TcpListener(const std::string &bindAddress, uint16_t port, int32_t backlog, SocketOption options);
        TcpListener(const TcpListener &other);
        TcpListener(TcpListener &&other) noexcept;
        TcpListener operator=(const TcpListener &other);
        TcpListener operator=(TcpListener &&other) noexcept;
        bool start();
        bool accept(Socket &client);
        void close();
        uint16_t getPort() const { return port; }
    private:
        Socket listener;
        std::string bindAddress;
        uint16_t port;
        int32_t backlog;
        SocketOption options;
    };

    class SslException : public std::exception {
    public:
        SslException(const char* message) : message_(message) {}

        const char *what() const noexcept override {
            return message_.c_str();
        }
    private:
        std::string message_;
    };

    class SslContext {
    public:
        SslContext();
        SslContext(SSL_CTX *sslContext);
        SslContext(const SslContext &other);
        SslContext(SslContext &&other) noexcept;
        SslContext& operator=(const SslContext &other);
        SslContext& operator=(SslContext &&other) noexcept;
        void dispose();
        SSL_CTX *getContext() const;
        bool isServerContext() const;
        bool initialize(const char *certificatePath, const char *privateKeyPath);
    private:
        SSL_CTX *context;
    };

    class SslStream {
    public:
        SslStream();
        //Used to create an SslStream for incoming connections
        SslStream(Socket socket, SslContext sslContext);
        //Used to create an SslStream for outgoing connections
        SslStream(Socket socket, SslContext sslContext, const char *hostName);
        SslStream(const SslStream &other);
        SslStream(SslStream &&other) noexcept;
        SslStream& operator=(const SslStream &other);
        SslStream& operator=(SslStream &&other) noexcept;
        int32_t readByte();
        ssize_t read(void *buffer, size_t size);
        ssize_t write(const void *buffer, size_t size);
        ssize_t peek(void *buffer, size_t size);
        void close();
        bool isSet() const;
    private:
        SSL *ssl;
    };

    class NetworkStream {
    public:
        NetworkStream();
        NetworkStream(Socket socket);
        NetworkStream(Socket &socket, SslStream ssl);
        NetworkStream(const NetworkStream &other);
        NetworkStream(NetworkStream &&other) noexcept;
        NetworkStream& operator=(const NetworkStream &other);
        NetworkStream& operator=(NetworkStream &&other) noexcept;
        int32_t readByte();
        ssize_t read(void *buffer, size_t size);
        ssize_t write(const void *buffer, size_t size);
        ssize_t peek(void *buffer, size_t size);
        void close();
        bool isSecure() const;
    private:
        Socket socket;
        SslStream ssl;
    };

    class IContentStream {
    public:
        virtual ssize_t writeTo(NetworkStream stream) = 0;
    };

    class TextStream : public IContentStream {
    public:
        TextStream();
        TextStream(const std::string &text);
        TextStream(const TextStream &other);
        TextStream(TextStream &&other) noexcept;
        TextStream& operator=(const TextStream &other);
        TextStream& operator=(TextStream &&other) noexcept;
        ssize_t writeTo(NetworkStream stream) override;
    private:
        std::string text;
    };

    class FileStream : public IContentStream {
    public:
        FileStream();
        FileStream(const std::string &filePath);
        FileStream(const FileStream &other);
        FileStream(FileStream &&other);
        FileStream& operator=(const FileStream &other);
        FileStream& operator=(FileStream &&other);
        ssize_t writeTo(NetworkStream stream) override;
    private:
        std::string filePath;
    };

    class File {
    public:
        static bool exists(const std::string &filePath);
        static bool isWithinDirectory(const std::string &filePath, const std::string &directoryPath);
        static size_t getSize(const std::string &filePath);
        static std::string getExtension(const std::string &filePath);
        static std::string readAllText(const std::string &filePath);
    };

    class String {
    public:
        static bool contains(const std::string &haystack, const std::string &needle);
        static bool startsWith(const std::string &haystack, const std::string &needle);
        static bool endsWith(const std::string &haystack, const std::string &needle);
        static std::string trim(const std::string &s);
        static std::string trimStart(const std::string &s);
        static std::string trimEnd(const std::string &s);
        static std::string toLower(const std::string &s);
        static std::string toUpper(const std::string &s);
        static std::vector<std::string> split(const std::string &s, const std::string &separator);
        static ssize_t indexOf(const std::string &str, const std::string &subStr);
        static std::string subString(const std::string &str, size_t startIndex, size_t length);
        static void replace(std::string &haystack, const std::string &needle, const std::string &replacement);
        template <typename T>
        static bool parseNumber(const std::string& str, T& number) {
            static_assert(std::is_arithmetic<T>::value, "T must be a numeric type");
            std::istringstream iss(str);
            iss >> number;
            return !iss.fail() && iss.eof();
        }
    };

    enum class HeaderError {
        None,
        FailedToPeek,
        FailedToRead,
        EndNotFound,
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

    enum class HttpStatusCode : int {
        // Informational 1xx
        Continue = 100,
        SwitchingProtocols = 101,
        Processing = 102,

        // Successful 2xx
        OK = 200,
        Created = 201,
        Accepted = 202,
        NonAuthoritativeInformation = 203,
        NoContent = 204,
        ResetContent = 205,
        PartialContent = 206,
        MultiStatus = 207,
        AlreadyReported = 208,
        IMUsed = 226,

        // Redirection 3xx
        MultipleChoices = 300,
        MovedPermanently = 301,
        Found = 302,
        SeeOther = 303,
        NotModified = 304,
        UseProxy = 305,
        SwitchProxy = 306,
        TemporaryRedirect = 307,
        PermanentRedirect = 308,

        // Client Error 4xx
        BadRequest = 400,
        Unauthorized = 401,
        PaymentRequired = 402,
        Forbidden = 403,
        NotFound = 404,
        MethodNotAllowed = 405,
        NotAcceptable = 406,
        ProxyAuthenticationRequired = 407,
        RequestTimeout = 408,
        Conflict = 409,
        Gone = 410,
        LengthRequired = 411,
        PreconditionFailed = 412,
        PayloadTooLarge = 413,
        URITooLong = 414,
        UnsupportedMediaType = 415,
        RangeNotSatisfiable = 416,
        ExpectationFailed = 417,
        IAmATeapot = 418,
        MisdirectedRequest = 421,
        UnprocessableEntity = 422,
        Locked = 423,
        FailedDependency = 424,
        UpgradeRequired = 426,
        PreconditionRequired = 428,
        TooManyRequests = 429,
        RequestHeaderFieldsTooLarge = 431,
        UnavailableForLegalReasons = 451,

        // Server Error 5xx
        InternalServerError = 500,
        NotImplemented = 501,
        BadGateway = 502,
        ServiceUnavailable = 503,
        GatewayTimeout = 504,
        HTTPVersionNotSupported = 505,
        VariantAlsoNegotiates = 506,
        InsufficientStorage = 507,
        LoopDetected = 508,
        NotExtended = 510,
        NetworkAuthenticationRequired = 511
    };

    using Headers = std::unordered_map<std::string,std::string>;

    struct HttpRequest {
        HttpMethod method;
        std::string path;
        Headers headers;
        bool getHeaderValue(const std::string &key, std::string &value) {
            if(headers.count(key)) {
                value = headers[key];
                return true;
            }
            return false;
        }
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
        int statusCode;
        Headers headers;
        HttpResponse(HttpStatusCode statusCode) {
            this->statusCode = static_cast<int>(statusCode);
        }
        void setHeader(const std::string &key, const std::string &value) {
            headers[key] = value;
        }
        void send(NetworkStream connection, IContentStream *content = nullptr) {
            std::string response = "HTTP/1.1 " + std::to_string(statusCode) + "\r\n";
            for(const auto &item : headers) {
                response += item.first + ": " + item.second + "\r\n";
            }
            response += "\r\n";
            connection.write(response.c_str(), response.size());
            if(content != nullptr) {
                content->writeTo(connection);
            }
        }
    };

    struct Configuration {
        uint16_t port;
        uint16_t portHttps;
        uint32_t maxHeaderSize;
        std::string bindAddress;
        std::string certificatePath;
        std::string privateKeyPath;
        std::string hostName;
        bool useHttps;
        bool useHttpsForwarding;

        void loadDefault() {
            port = 8080;
            portHttps = 8081;
            maxHeaderSize = 8192;
            bindAddress = "0.0.0.0";
            certificatePath = "cert.pem";
            privateKeyPath = "key.pem";
            hostName = "localhost";
            useHttps = true;
            useHttpsForwarding = true;
        }
    };

    using RequestHandler = std::function<void(NetworkStream connection, HttpRequest &request)>;

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