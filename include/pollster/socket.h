#ifndef pollster_socket_h_
#define pollster_socket_h_

#if defined(_MSC_VER)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <windows.h>

#undef gai_strerror
#define gai_strerror gai_strerrorA
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#endif
