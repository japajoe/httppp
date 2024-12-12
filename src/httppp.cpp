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

#include "httppp.h"
#include <utility> 
#include <algorithm>
#include <future>
#include <sstream>
#include <stdexcept>
#include <signal.h>

#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif

namespace httppp {
    //////////////////////////
    /////////[Socket]/////////
    //////////////////////////

#ifdef _WIN32
    static bool winsockInitialized = false;
#endif

    static void initializeWinsock2() {
    #ifdef _WIN32
        if(winsockInitialized)
            return;
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
            printf("Failed to initialize winsock\n")
            winsockInitialized = true;
        }
    #endif        
    }

    Socket::Socket() {
        initializeWinsock2();
        std::memset(&s, 0, sizeof(socket_t));
        s.fd = -1;
    }

    Socket::Socket(AddressFamily addressFamily) {
        initializeWinsock2();
        std::memset(&s, 0, sizeof(socket_t));
        s.fd = socket(static_cast<int>(addressFamily), SOCK_STREAM, 0);
    #ifdef _WIN32
        if(s.fd == INVALID_SOCKET)
            s.fd = -1;
    #endif
    }

    Socket::Socket(const Socket &other) {
        s = other.s;
    }

    Socket::Socket(Socket &&other) noexcept {
        s = std::move(other.s);
    }

    Socket& Socket::operator=(const Socket &other) {
        if(this != &other) {
            s = other.s;
        }
        return *this;
    }

    Socket& Socket::operator=(Socket &&other) noexcept {
        if(this != &other) {
            s = std::move(other.s);
        }
        return *this;
    }

    void Socket::close() {
    #ifdef _WIN32
        closesocket(s.fd);
    #else
        ::close(s.fd);
    #endif
        s.fd = -1;
    }
    
    bool Socket::bind(const std::string &bindAddress, uint16_t port) {
        sockaddr_in_t address = {0};
        address.sin_family = AF_INET;

        struct in_addr addr;

        if (inet_pton(AF_INET, bindAddress.c_str(), &addr) <= 0)
            return false;

        address.sin_addr.s_addr = INADDR_ANY;
        std::memcpy(&address.sin_addr.s_addr, &addr, sizeof(addr));
        
        address.sin_port = htons(port);

        std::memcpy(&s.address.ipv4, &address, sizeof(sockaddr_in_t));

        return ::bind(s.fd, (struct sockaddr*)&s.address.ipv4, sizeof(sockaddr_in_t)) == SOCKET_ERROR ? false : true;
    }

    IPVersion Socket::detectIPVersion(const std::string &ip) {
        struct sockaddr_in sa;
        struct sockaddr_in6 sa6;

        // Try to convert to IPv4
        if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1)
            return IPVersion::IPv4;

        // Try to convert to IPv6
        if (inet_pton(AF_INET6, ip.c_str(), &(sa6.sin6_addr)) == 1)
            return IPVersion::IPv6;

        return IPVersion::Invalid;
    }

    bool Socket::connect(const std::string &ip, uint16_t port) {
        IPVersion version = detectIPVersion(ip);

        switch(version) {
            case IPVersion::IPv4: {
                s.address.ipv4.sin_family = AF_INET;
                s.address.ipv4.sin_port = htons(port);
                inet_pton(AF_INET, ip.c_str(), &s.address.ipv4.sin_addr);
                return ::connect(s.fd, (struct sockaddr*)&s.address.ipv4, sizeof(s.address.ipv4)) == SOCKET_ERROR ? false : true;
            }
            case IPVersion::IPv6: {
                s.address.ipv6.sin6_family = AF_INET6;
                s.address.ipv6.sin6_port = htons(port);
                inet_pton(AF_INET6, ip.c_str(), &s.address.ipv6.sin6_addr);
                return ::connect(s.fd, (struct sockaddr*)&s.address.ipv6, sizeof(s.address.ipv6)) == SOCKET_ERROR ? false : true;
            }
            default:
                return false;
        }
    }

    bool Socket::listen(int32_t backlog) {
        return ::listen(s.fd, backlog) == SOCKET_ERROR ? false : true;
    }

    bool Socket::accept(Socket &socket) {
        sockaddr_in_t clientAddr;
        uint32_t addrLen = sizeof(clientAddr);

        int clientFD = -1;

    #ifdef _WIN32
        clientFD = accept(s.fd, (struct sockaddr*)&clientAddr, (int32_t*)&addrLen);
        
        if(clientFD == INVALID_SOCKET)
            clientFD = -1;
    #else
        clientFD = ::accept(s.fd, (struct sockaddr*)&clientAddr, &addrLen);
    #endif

        if (clientFD == -1)
            return false;

        socket.s.fd = clientFD;
        std::memcpy(&socket.s.address, &clientAddr, sizeof(sockaddr_in_t));

        return true;
    }

    bool Socket::setOption(int level, int option, const void *value, uint32_t valueSize) {
    #ifdef _WIN32
        return setsockopt(s.fd, level, option, (char*)value, valueSize) != 0 ? false : true;
    #else
        return setsockopt(s.fd, level, option, value, valueSize) != 0 ? false : true;
    #endif
    }

    void Socket::setNonBlocking() {
    #ifdef _WIN32
        u_long mode = 1; // 1 to enable non-blocking socket
        if (ioctlsocket(s.fd, FIONBIO, &mode) != 0) {
            printf("Failed to set non-blocking mode\n");
        }
    #else
        int flags = fcntl(s.fd, F_GETFL, 0);
        fcntl(s.fd, F_SETFL, flags | O_NONBLOCK);
    #endif
    }

    int32_t Socket::readByte() {
        unsigned char b = 0;
    #ifdef _WIN32
        if(recv(s.fd, (char*)&b, 1, 0) > 0)
            return static_cast<int32_t>(b);
    #else
        if(recv(s.fd, &b, 1, 0) > 0)
            return static_cast<int32_t>(b);
    #endif
        return -1;
    }

    ssize_t Socket::read(void *buffer, size_t size) {
    #ifdef _WIN32
        return recv(s.fd, (char*)buffer, size, 0);
    #else
        return recv(s.fd, buffer, size, 0);
    #endif
    }

    ssize_t Socket::write(const void *buffer, size_t size) {
    #ifdef _WIN32
        return send(s.fd, (char*)data, size, 0);
    #else
        return send(s.fd, buffer, size, 0);
    #endif
    }

    ssize_t Socket::peek(void *buffer, size_t size) {
    #ifdef _WIN32
        return recv(s.fd, (char*)buffer, size, MSG_PEEK);
    #else
        return recv(s.fd, buffer, size, MSG_PEEK);
    #endif
    }

    //To do: figure out better way than just passing the ipv4 address
    ssize_t Socket::receiveFrom(void *buffer, size_t size) {
        socklen_t clientLen = sizeof(s.address.ipv4);
    #ifdef _WIN32
        return recvfrom(s.fd, (char*)buffer, size, 0, reinterpret_cast<struct sockaddr*>(&s.address.ipv4), &clientLen);
    #else
        return recvfrom(s.fd, buffer, size, 0, reinterpret_cast<struct sockaddr*>(&s.address.ipv4), &clientLen);
    #endif
    }

    //To do: figure out better way than just passing the ipv4 address
    ssize_t Socket::sendTo(const void *buffer, size_t size) {
        socklen_t clientLen = sizeof(s.address.ipv4);
    #ifdef _WIN32
        return sendto(s.fd, (char*)buffer, size, 0, reinterpret_cast<struct sockaddr*>(&s.address.ipv4), clientLen);
    #else
        return sendto(s.fd, buffer, size, 0, reinterpret_cast<struct sockaddr*>(&s.address.ipv4), clientLen);
    #endif
    }

    int32_t Socket::getFileDescriptor() const {
        return s.fd;
    }

    bool Socket::isSet() const { 
        return s.fd >= 0; 
    }

    //////////////////////////
    //////[TcpListener]///////
    //////////////////////////

    TcpListener::TcpListener() {
        this->bindAddress = "0.0.0.0";
        this->port = 80;
        this->backlog = 10;
        this->options = SocketOption_None;
    }

    TcpListener::TcpListener(const std::string &bindAddress, uint16_t port, int32_t backlog, SocketOption options) {
        this->bindAddress = bindAddress;
        this->port = port;
        this->backlog = backlog;
        this->options = options;
    }

    TcpListener::TcpListener(const TcpListener &other) {
        listener = other.listener;
        bindAddress = other.bindAddress;
        port = other.port;
        backlog = other.backlog;
        options = other.options;
    }

    TcpListener::TcpListener(TcpListener &&other) noexcept {
        listener = std::move(other.listener);
        bindAddress = std::move(other.bindAddress);
        port = other.port;
        backlog = other.backlog;
        options = other.options;
    }

    TcpListener TcpListener::operator=(const TcpListener &other) {
        if(this != &other) {
            listener = other.listener;
            bindAddress = other.bindAddress;
            port = other.port;
            backlog = other.backlog;
            options = other.options;
        }
        return *this;
    }

    TcpListener TcpListener::operator=(TcpListener &&other) noexcept {
        if(this != &other) {
            listener = std::move(other.listener);
            bindAddress = std::move(other.bindAddress);
            port = other.port;
            backlog = other.backlog;
            options = other.options;
        }
        return *this;
    }

    bool TcpListener::start() {
        if(listener.getFileDescriptor() >= 0)
            return false;

        listener = Socket(AddressFamily::AFInet);

        int reuse = 1;

        if(options & SocketOption_Reuse) {
            if(!listener.setOption(SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
                listener.close();
                return false;
            }
        }

        if(options & SocketOption_NonBlocking)
            listener.setNonBlocking();
        
        if(!listener.bind(bindAddress, port)) {
            listener.close();
            return false;
        }

        if(!listener.listen(backlog)) {
            listener.close();
            return false;
        }

        return true;
    }

    bool TcpListener::accept(Socket &client) {
        if(listener.getFileDescriptor() < 0)
            return false;

        if(listener.accept(client))
            return true;

        return false;
    }

    void TcpListener::close() {
        if(listener.getFileDescriptor() >= 0)
            listener.close();
    }

    //////////////////////////
    ///////[SslContext]///////
    //////////////////////////

    SslContext::SslContext() {
        this->context = SSL_CTX_new(TLS_method());
    }

    SslContext::SslContext(SSL_CTX *sslContext) {
        this->context = sslContext;
    }

    SslContext::SslContext(const std::string &certificatePath, const std::string &privateKeyPath) {
        context = SSL_CTX_new(TLS_server_method());

        if(context == nullptr) {
            throw SslException("Failed to create SSL context");
        }
        
        if (SSL_CTX_use_certificate_file(context, certificatePath.c_str(), SSL_FILETYPE_PEM) <= 0) {
            SSL_CTX_free(context);
            context = nullptr;
            throw SslException("Failed to use certificate file");
        }

        if (SSL_CTX_use_PrivateKey_file(context, privateKeyPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
            SSL_CTX_free(context);
            context = nullptr;
            throw SslException("Failed to use private key file");
        }

        if (!SSL_CTX_check_private_key(context)) {
            SSL_CTX_free(context);
            context = nullptr;
            throw SslException("Failed to check private key");
        }
    }

    SslContext::SslContext(const SslContext &other) {
        context = other.context;
    }

    SslContext::SslContext(SslContext &&other) noexcept {
        context = std::move(other.context);
    }

    SslContext& SslContext::operator=(const SslContext &other) {
        if(this != &other) {
            context = other.context;
        }
        return *this;
    }

    SslContext& SslContext::operator=(SslContext &&other) noexcept {
        if(this != &other) {
            context = std::move(other.context);
        }
        return *this;
    }

    void SslContext::dispose() {
        if(context) {
            SSL_CTX_free(context);
            context = nullptr;
        }
    }

    SSL_CTX *SslContext::getContext() {
        return context;
    }

    //////////////////////////
    ////////[SslStream]///////
    //////////////////////////

    SslStream::SslStream() {
        this->ssl = nullptr;
    }

    SslStream::SslStream(Socket socket, SslContext sslContext) {
        if(socket.isSet() && sslContext.getContext()) {
            ssl = SSL_new(sslContext.getContext());

            if(ssl == nullptr)
                throw SslException("Failed to create SSL instance");

            SSL_set_fd(ssl, socket.getFileDescriptor());

            if (SSL_accept(ssl) <= 0) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                ssl = nullptr;
                throw SslException("Failed to SSL accept");
            }
        }
    }

    SslStream::SslStream(Socket socket, SslContext sslContext, const char *hostName) {
        if(socket.isSet() && sslContext.getContext()) {
            ssl = SSL_new(sslContext.getContext());

            if(ssl == nullptr)
                throw SslException("Failed to create SSL instance");

            SSL_set_fd(ssl, socket.getFileDescriptor());
            
            if(hostName)
                SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void*)hostName);

            if (SSL_connect(ssl) != 1) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                ssl = nullptr;
                throw SslException("Failed to SSL connect");
            }
        }
    }

    SslStream::SslStream(const SslStream &other) {
        ssl = other.ssl;
    }

    SslStream::SslStream(SslStream &&other) noexcept {
        ssl = std::exchange(other.ssl, nullptr);
    }

    SslStream& SslStream::operator=(const SslStream &other) {
        if(this != &other) {
            ssl = other.ssl;
        }
        return *this;
    }

    SslStream& SslStream::operator=(SslStream &&other) noexcept {
        if(this != &other) {
            ssl = std::exchange(other.ssl, nullptr);
        }
        return *this;
    }

    int32_t SslStream::readByte() {
        if(!ssl)
            return -1;
        unsigned char b = 0;
        if(SSL_read(ssl, &b, 1) > 0)
            return static_cast<int32_t>(b);
        return -1;
    }

    ssize_t SslStream::read(void *buffer, size_t size) {
        if(ssl) {
            int bytesRead = SSL_read(ssl, buffer, size);
            if(bytesRead <= 0) {
                int errorCode = SSL_get_error(ssl, bytesRead);
                printf("SSL_read error code: %d\n", errorCode);
            }
            return bytesRead;
        }
        return 0;
    }

    ssize_t SslStream::write(const void *buffer, size_t size) {
        if(ssl)
            return SSL_write(ssl, buffer, size);
        return 0;
    }

    ssize_t SslStream::peek(void *buffer, size_t size) {
        if(ssl)
            return SSL_peek(ssl, buffer, size);
        return 0;
    }

    void SslStream::close() {
        if(ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
    }

    bool SslStream::isSet() const {
        return ssl != nullptr;
    }

    //////////////////////////
    //////[NetworkStream]/////
    //////////////////////////

    NetworkStream::NetworkStream() {

    }

    NetworkStream::NetworkStream(const Socket &socket) {
        this->socket = socket;
    }

    NetworkStream::NetworkStream(const Socket &socket, const SslStream &ssl) {
        this->socket = socket;
        this->ssl = ssl;
    }

    NetworkStream::NetworkStream(const NetworkStream &other) {
        socket = other.socket;
        ssl = other.ssl;
    }

    NetworkStream::NetworkStream(NetworkStream &&other) noexcept {
        socket = std::move(other.socket);
        ssl = std::move(other.ssl);
    }

    NetworkStream& NetworkStream::operator=(const NetworkStream &other) {
        if(this != &other) {
            socket = other.socket;
            ssl = other.ssl;
        }
        return *this;
    }

    NetworkStream& NetworkStream::operator=(NetworkStream &&other) noexcept {
        if(this != &other) {
            socket = std::move(other.socket);
            ssl = std::move(other.ssl);
        }
        return *this;
    }

    int32_t NetworkStream::readByte() {
        if(ssl.isSet())
            return ssl.readByte();
        else
            return socket.readByte();
    }

    ssize_t NetworkStream::read(void *buffer, size_t size) {
        if(ssl.isSet())
            return ssl.read(buffer, size);
        else
            return socket.read(buffer, size);
    }

    ssize_t NetworkStream::write(const void *buffer, size_t size) {
        if(ssl.isSet())
            return ssl.write(buffer, size);
        else
            return socket.write(buffer, size);
    }

    ssize_t NetworkStream::peek(void *buffer, size_t size) {
        if(ssl.isSet())
            return ssl.peek(buffer, size);
        else
            return socket.peek(buffer, size);
    }

    void NetworkStream::close() {
        if(ssl.isSet())
            ssl.close();
        socket.close();
    }

    bool NetworkStream::isSecure() const {
        return ssl.isSet();
    }

    //////////////////////////
    /////////[String]/////////
    //////////////////////////

    bool String::contains(const std::string &haystack, const std::string &needle) {
        return haystack.find(needle) != std::string::npos;
    }

    bool String::startsWith(const std::string &haystack, const std::string &needle) {
        if (haystack.length() >= needle.length()) 
            return (0 == haystack.compare(0, needle.length(), needle));
        return false;
    }

    bool String::endsWith(const std::string &haystack, const std::string &needle) {
        if (haystack.length() >= needle.length()) 
            return (0 == haystack.compare(haystack.length() - needle.length(), needle.length(), needle));
        return false;
    }

    std::string String::trim(const std::string &s) {
        // Find the first non-whitespace character from the beginning
        size_t start = s.find_first_not_of(" \t\n\r\f\v");

        // Find the last non-whitespace character from the end
        size_t end = s.find_last_not_of(" \t\n\r\f\v");

        // Handle the case where the string is all whitespace
        if (start == std::string::npos)
            return "";

        // Extract the substring between start and end
        return s.substr(start, end - start + 1);
    }

    std::string String::trimStart(const std::string &s) {
        size_t start = s.find_first_not_of(" \t\n\r\f\v");

        if (start == std::string::npos)
            return "";

        // Extract the substring starting from the first non-whitespace character
        return s.substr(start);
    }

    std::string String::trimEnd(const std::string &s) {
        size_t end = s.find_last_not_of(" \t\n\r\f\v");

        if (end == std::string::npos)
            return "";

        // Extract the substring from the beginning to the last non-whitespace character
        return s.substr(0, end + 1);
    }

    std::string String::toLower(const std::string &s) {
        std::string result = s;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }

    std::string String::toUpper(const std::string &s) {
        std::string result = s;
        std::transform(result.begin(), result.end(), result.begin(), ::toupper);
        return result;
    }

    std::vector<std::string> String::split(const std::string &s, const std::string &separator) {
        std::vector<std::string> substrings;
        size_t start = 0;
        size_t end;

        // Find all occurrences of separator and split the string
        while ((end = s.find(separator, start)) != std::string::npos) {
            substrings.push_back(s.substr(start, end - start));
            start = end + separator.length();
        }

        // Add the last part of the string after the last separator
        substrings.push_back(s.substr(start));

        return substrings;
    }

    //////////////////////////
    /////////[Server]/////////
    //////////////////////////    

    enum class SignalType : int {
        SigInt = SIGINT,
#ifndef _WIN32
        SigPipe = SIGPIPE,
#endif
    };

    typedef void (*signal_handler_t)(int);

    void registerSignal(SignalType signalType, signal_handler_t handler) {
    #ifdef _WIN32
        __p_sig_fn_t h = static_cast<__p_sig_fn_t>(handler);
        signal(static_cast<int>(signalType), h);
    #else
        __sighandler_t h = static_cast<__sighandler_t>(handler);
        signal(static_cast<int>(signalType), h);
    #endif
    }

    static std::vector<Server*> servers;

    static void signalHandler(int signum) {
    #ifdef _WIN32
        switch(signum) {
            case SIGINT:
                for(auto server : servers) {
                    if(server)
                        server->stop();
                }
                break;
            default:
                break;
        }
    #else
        switch(signum) {
            case SIGINT:
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
    #endif
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
        const size_t bufferSize = 1024;
        char buffer[bufferSize];
        size_t headerEnd = 0;
        size_t totalHeaderSize = 0;
        bool endFound = false;

        // Peek to find the end of the header
        while (true) {
            ssize_t bytesPeeked = socket.peek(buffer, bufferSize);

            totalHeaderSize += bytesPeeked;

            if(totalHeaderSize > configuration.maxHeaderSize) {
                printf("HeaderError::MaxSizeExceeded\n");
                return HeaderError::MaxSizeExceeded;
            }

            if (bytesPeeked < 0) {
                printf("HeaderError::FailedToPeek\n");
                return HeaderError::FailedToPeek;
            }

            //Don't loop indefinitely...
            if(bytesPeeked == 0) {
                break;
            }
            
            // Look for the end of the header (double CRLF)
            const char* endOfHeader = std::search(buffer, buffer + bytesPeeked, "\r\n\r\n", "\r\n\r\n" + 4);
            if (endOfHeader != buffer + bytesPeeked) {
                headerEnd = endOfHeader - buffer + 4; // Include the length of the CRLF
                endFound = true;
                break;
            }
        }

        if(!endFound) {
            printf("HeaderError::EndNotFound\n");
            return HeaderError::EndNotFound;
        }

        // Now read the header
        header.resize(headerEnd);
        ssize_t bytesRead = socket.read(&header[0], headerEnd);
        if (bytesRead < 0) {
            printf("HeaderError::FailedToRead\n");
            return HeaderError::FailedToRead;
        }

        if(header.size() > configuration.maxHeaderSize) {
            printf("HeaderError::MaxSizeExceeded\n");
            return HeaderError::MaxSizeExceeded;
        }

        return HeaderError::None;
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
    #ifdef _WIN32
        registerSignal(SignalType::SigInt, &signalHandler);
    #else
        registerSignal(SignalType::SigInt, &signalHandler);
        registerSignal(SignalType::SigPipe, &signalHandler);
    #endif
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