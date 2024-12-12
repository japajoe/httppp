#ifndef HTTPPP_HTTPPP_HPP
#define HTTPPP_HTTPPP_HPP

#include <string>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <exception>
#include <sstream>
#include <type_traits>

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

#include <openssl/ssl.h>

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
        SslContext(const std::string &certificatePath, const std::string &privateKeyPath);
        SslContext(const SslContext &other);
        SslContext(SslContext &&other) noexcept;
        SslContext& operator=(const SslContext &other);
        SslContext& operator=(SslContext &&other) noexcept;
        void dispose();
        SSL_CTX *getContext();
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
    private:
        SSL *ssl;
    };

    class NetworkStream {
    public:
        NetworkStream();
        NetworkStream(const Socket &socket);
        NetworkStream(const Socket &socket, const SslStream &ssl);
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
        bool secure;
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
        template <typename T>
        static bool parseNumber(const std::string& str, T& number) {
            // Check if T is a numeric type
            static_assert(std::is_arithmetic<T>::value, "T must be a numeric type");

            std::istringstream iss(str);
            iss >> number;

            // Check if the conversion was successful
            return !iss.fail() && iss.eof();
        }
    };
}

#endif