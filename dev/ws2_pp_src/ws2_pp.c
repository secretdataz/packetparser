#include <string.h>
#define INCL_WINSOCK_API_PROTOTYPES 0
#define INCL_WINSOCK_API_TYPEDEFS 1
#define WINSOCK_API_LINKAGE
#include <winsock2.h>
#include <shlobj.h>
#include <ws2spi.h>

// hack to exclude down-level inline code, which depends on ws2_32
// calls, which are not available due to INCL_WINSOCK_API_PROTOTYPES
#define _WSPIAPI_H_
#include <ws2tcpip.h>
#undef _WSPIAPI_H_

#include <sporder.h>

// code assumes 32-bit pointers
#if ((!defined(_WIN32) && !defined(WIN32)) || (defined(_WIN64) || defined(WIN64)))
    #error x64 platform is not supported!
#endif

// Definitions
//

// including <btypes.h>
#ifndef __cplusplus
    #ifndef __bool_true_false_are_defined
        typedef char bool;
        #define false ((bool)(1==0))
        #define true  ((bool)(1==1))
        #define __bool_true_false_are_defined
    #endif
#endif
#ifndef _WCHAR_T_DEFINED
    typedef unsigned short wchar_t;
    #define _WCHAR_T_DEFINED
    #define WCHAR_MIN 0
    #define WCHAR_MAX ((wchar_t)-1)
#endif  /* _WCHAR_T_DEFINED */
#define BUFP(p,pos) (((unsigned char*)(p)) + (pos))
#ifndef _ARRAYSIZE
    #define _ARRAYSIZE(x) (sizeof(x)/sizeof((x)[0]))
#endif  /* _ARRAYSIZE */
// end of <btypes.h>

// including <sock.h>
#define SOCK_JOINIP(a,b,c,d) ( ( ( (a)&0xFF ) << 24 ) | ( ( (b)&0xFF ) << 16 ) | ( ( (c)&0xFF ) << 8 ) | ( (d)&0xFF ) )
#define SOCK_SPLITIP(ip) ( ( (ip) >> 24 )&0xFF ), ( ( (ip) >> 16 )&0xFF ), ( ( (ip) >> 8 )&0xFF ), ( (ip)&0xFF )
// end if <sock.h>

typedef void (__stdcall* LPFNSETDLLDIRECTORYA)(LPCSTR lpPathName);

// Entrance
//

static bool use_dll = TRUE;

static SOCKET l_hSock = INVALID_SOCKET;
static HINSTANCE l_hRealDll = NULL;
static HINSTANCE l_hFakeDll = NULL;
static struct WSFUNCS
{
    LPFN_CLOSESOCKET closesocket;
    LPFN_CONNECT connect;
    LPFN_HTONL htonl;
    LPFN_HTONS htons;
    LPFN_IOCTLSOCKET ioctlsocket;
    LPFN_INET_ADDR inet_addr;
    LPFN_INET_NTOA inet_ntoa;
    LPFN_NTOHL ntohl;
    LPFN_NTOHS ntohs;
    LPFN_RECV recv;
    LPFN_SELECT select;
    LPFN_SEND send;
    LPFN_SENDTO sendto;
    LPFN_SETSOCKOPT setsockopt;
    LPFN_SHUTDOWN shutdown;
    LPFN_SOCKET socket;
    LPFN_GETHOSTBYNAME gethostbyname;
    LPFN_GETHOSTNAME gethostname;
    LPFN_WSAGETLASTERROR WSAGetLastError;
    LPFN_WSASTARTUP WSAStartup;
    LPFN_WSACLEANUP WSACleanup;
}
l_WsFuncs = { 0 };

// Stubs
//

int __stdcall closesocket(SOCKET s)
{
    return l_WsFuncs.closesocket(s);
}

int __stdcall connect(SOCKET s, const struct sockaddr* name, int namelen)
{
    return l_WsFuncs.connect(s, name, namelen);
}

int __stdcall ioctlsocket(SOCKET s, long cmd, u_long* argp)
{
    return l_WsFuncs.ioctlsocket(s, cmd, argp);
}

u_long __stdcall htonl(u_long hostlong)
{
    return l_WsFuncs.htonl(hostlong);
}

u_short __stdcall htons(u_short hostshort)
{
    return l_WsFuncs.htons(hostshort);
}

unsigned long __stdcall inet_addr(const char* cp)
{
    return l_WsFuncs.inet_addr(cp);
}

char* __stdcall inet_ntoa(struct in_addr in)
{
    return l_WsFuncs.inet_ntoa(in);
}

u_long __stdcall ntohl(u_long netlong)
{
    return l_WsFuncs.ntohl(netlong);
}

u_short __stdcall ntohs(u_short netshort)
{
    return l_WsFuncs.ntohs(netshort);
}

int __stdcall recv(SOCKET s, char* buf, int len, int flags)
{
    // recv first
    int n = l_WsFuncs.recv(s, buf, len, flags);

    if(use_dll && n && n!=SOCKET_ERROR)
    {
        char szBuffer[32];

        wsprintfA(szBuffer, "RR");//,%u,", (unsigned int)n);
        l_WsFuncs.send(l_hSock, szBuffer, lstrlenA(szBuffer), 0);
        l_WsFuncs.send(l_hSock, buf, n, 0);
    }

    return n;
}

int __stdcall select(int nfds, fd_set* readfds, fd_set* writefds, fd_set*exceptfds, const struct timeval* timeout)
{
    return l_WsFuncs.select(nfds, readfds, writefds, exceptfds, timeout);
}

int __stdcall send(SOCKET s, const char* buf, int len, int flags)
{
    // send first, since we are not interested what the program sends
    // but what actually got sent.
    int n = l_WsFuncs.send(s, buf, len, flags);

    if(use_dll && n && n!=SOCKET_ERROR)
    {
        char szBuffer[32];

        wsprintfA(szBuffer, "SS");//,%u,", (unsigned int)n);
        l_WsFuncs.send(l_hSock, szBuffer, lstrlenA(szBuffer), 0);
        l_WsFuncs.send(l_hSock, buf, n, 0);
    }

    return n;
}

int __stdcall sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
    return l_WsFuncs.sendto(s, buf, len, flags, to, tolen);
}

int __stdcall setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen)
{
    return l_WsFuncs.setsockopt(s, level, optname, optval, optlen);
}

SOCKET __stdcall socket(int af, int type, int protocol)
{
    return l_WsFuncs.socket(af, type, protocol);
}

struct hostent* __stdcall gethostbyname(const char* name)
{
    return l_WsFuncs.gethostbyname(name);
}

int __stdcall gethostname(char* name, int namelen)
{
    return l_WsFuncs.gethostname(name, namelen);
}

int __stdcall WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData)
{
    return l_WsFuncs.WSAStartup(wVersionRequested, lpWSAData);
}

int __stdcall WSACleanup(void)
{
    return l_WsFuncs.WSACleanup();
}

int __stdcall WSAGetLastError(void)
{
    return l_WsFuncs.WSAGetLastError();
}

BOOL CALLBACK DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    char szSysPath[MAX_PATH], szLibPath[MAX_PATH];
    WSADATA Wsa;

    switch(dwReason)
    {
        case DLL_PROCESS_ATTACH:
            l_hFakeDll = hInstance;

            if(MessageBoxA(NULL, "Connect to Packet Parser?", "Packet Parser", MB_YESNO|MB_ICONQUESTION)==IDNO)
            {
                use_dll = FALSE;
            }

            {// rewrite system DLL load path
                LPFNSETDLLDIRECTORYA lpfnSetDllDirectoryA = (LPFNSETDLLDIRECTORYA)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "SetDllDirectoryA");

                if(lpfnSetDllDirectoryA)
                {
                    lpfnSetDllDirectoryA(".");
                }
            }

            GetSystemDirectoryA(szSysPath, _ARRAYSIZE(szSysPath));

            wsprintfA(szLibPath, "%s\\ws2_32.dll", szSysPath);

            l_hRealDll = LoadLibraryA(szLibPath);

            if(l_hRealDll)
            {
                if(l_hRealDll==l_hFakeDll)
                {// oops
                    FreeLibrary(l_hRealDll);
                    l_hRealDll = NULL;
                    MessageBoxA(NULL, "Attempted self-load.", "Library Error", MB_OK|MB_ICONSTOP);
                    return FALSE;
                }

#define LOADFUNC(x,y) l_WsFuncs.y = (x)GetProcAddress(l_hRealDll, #y)
                LOADFUNC(LPFN_CLOSESOCKET,closesocket);
                LOADFUNC(LPFN_CONNECT,connect);
                LOADFUNC(LPFN_HTONL,htonl);
                LOADFUNC(LPFN_HTONS,htons);
                LOADFUNC(LPFN_IOCTLSOCKET,ioctlsocket);
                LOADFUNC(LPFN_INET_ADDR,inet_addr);
                LOADFUNC(LPFN_INET_NTOA,inet_ntoa);
                LOADFUNC(LPFN_NTOHL,ntohl);
                LOADFUNC(LPFN_NTOHS,ntohs);
                LOADFUNC(LPFN_RECV,recv);
                LOADFUNC(LPFN_SELECT,select);
                LOADFUNC(LPFN_SEND,send);
                LOADFUNC(LPFN_SENDTO,sendto);
                LOADFUNC(LPFN_SETSOCKOPT,setsockopt);
                LOADFUNC(LPFN_SHUTDOWN,shutdown);
                LOADFUNC(LPFN_SOCKET,socket);
                LOADFUNC(LPFN_GETHOSTBYNAME,gethostbyname);
                LOADFUNC(LPFN_GETHOSTNAME,gethostname);
                LOADFUNC(LPFN_WSAGETLASTERROR,WSAGetLastError);
                LOADFUNC(LPFN_WSASTARTUP,WSAStartup);
                LOADFUNC(LPFN_WSACLEANUP,WSACleanup);
#undef LOADFUNC
				if(use_dll)
				{
					if(l_WsFuncs.WSAStartup(MAKEWORD(2,2), &Wsa))
					{
						FreeLibrary(l_hRealDll);
						l_hRealDll = NULL;
						MessageBoxA(NULL, "Failed to initialize actual Windows Sockets.", "Library Error", MB_OK|MB_ICONSTOP);
						return FALSE;
					}

					if((l_hSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))==INVALID_SOCKET)
					{
						l_WsFuncs.WSACleanup();
						FreeLibrary(l_hRealDll);
						l_hRealDll = NULL;
						MessageBoxA(NULL, "Failed to create socket.", "Library Error", MB_OK|MB_ICONSTOP);
						return FALSE;
					}
					else
					{
						struct sockaddr_in sin;

						sin.sin_family = AF_INET;
						sin.sin_addr.s_addr = l_WsFuncs.htonl(SOCK_JOINIP(127,0,0,1));
						sin.sin_port = l_WsFuncs.htons(13554);

						if(connect(l_hSock, (struct sockaddr*)&sin, sizeof(sin))==SOCKET_ERROR)
						{
							l_WsFuncs.shutdown(l_hSock, SD_BOTH);
							l_WsFuncs.closesocket(l_hSock);
							l_hSock = INVALID_SOCKET;
							l_WsFuncs.WSACleanup();
							FreeLibrary(l_hRealDll);
							l_hRealDll = NULL;
							MessageBoxA(NULL, "Failed to connect to 127.0.0.1:13554 (TCP).", "Library Error", MB_OK|MB_ICONSTOP);
							use_dll = FALSE;
							//return FALSE;
						}
					}
				}
            }
            else
            {
                return FALSE;
            }
            break;
        case DLL_PROCESS_DETACH:
            if(l_hRealDll)
            {
                if(l_hSock!=INVALID_SOCKET)
                {
                    l_WsFuncs.shutdown(l_hSock, SD_BOTH);
                    l_WsFuncs.closesocket(l_hSock);
                    l_hSock = INVALID_SOCKET;
                }
                l_WsFuncs.WSACleanup();
                FreeLibrary(l_hRealDll);
                l_hRealDll = NULL;
            }
            l_hFakeDll = NULL;
            break;
    }
    return TRUE;

    // unused
    lpReserved;
}
