#include "prnetdb.h"
#include "prio.h"
#include "nspr.h"
#include "private/pprio.h"
#include "prlog.h"
#include "secport.h"
#include <string.h>

/* socks host must be an ip address or localhost */
/* - need callback to query for proxy host exceptions */
/* - need to configure tor to go through a proxy... */

static PRDescIdentity nsSOCKSIOLayerIdentity;
static PRIOMethods nsSOCKSIOLayerMethods;
static PRBool firstTime = PR_TRUE;
static PRBool ipv6Supported = PR_TRUE;

// A buffer of 262 bytes should be enough for any request and response
// in case of SOCKS4 as well as SOCKS5
static const uint32_t BUFFER_SIZE = 262;
static const uint32_t MAX_HOSTNAME_LEN = 255;

#if defined(PR_LOGGING)
static PRLogModuleInfo *gSOCKSLog;
#define LOGDEBUG(args) PR_LOG(gSOCKSLog, PR_LOG_DEBUG, args)
#define LOGERROR(args) PR_LOG(gSOCKSLog, PR_LOG_ERROR, args)
#else
#define LOGDEBUG(args)
#define LOGERROR(args)
#endif

#define LOG(args) PR_LOG(GetProxyLog(), PR_LOG_DEBUG, args)

#define IS_ASCII_SPACE(_c) ((_c) == ' ' || (_c) == '\t')

#if defined(PR_LOGGING)
static PRLogModuleInfo *
GetProxyLog()
{
    static PRLogModuleInfo *sLog;
    if (!sLog)
        sLog = PR_NewLogModule("sslproxy");
    return sLog;
}
#endif

// Required buffer size for text form of an IP address.
// Includes space for null termination. We make our own contants
// because we don't want higher-level code depending on things
// like INET6_ADDRSTRLEN and having to include the associated
// platform-specific headers.
#ifdef XP_WIN
// Windows requires longer buffers for some reason.
static const int kIPv4CStrBufSize = 22;
static const int kIPv6CStrBufSize = 65;
#else
static const int kIPv4CStrBufSize = 16;
static const int kIPv6CStrBufSize = 46;
#endif


/*
// apply mask to address (zeros out excluded bits).
//
// NOTE: we do the byte swapping here to minimize overall swapping.
*/

#if 0
can-use-proxy
    int32_t port;
    PRNetAddr addr;
    PRBool is_ipaddr = (PR_StringToNetAddr(host.get(), &addr) == PR_SUCCESS);
    SOCKS5SocketPRIPv6Addr ipv6;
    if (is_ipaddr) {
        // convert parsed address to IPv6
        if (addr.raw.family == PR_AF_INET) {
            // convert to IPv4-mapped address
            PR_ConvertIPv4AddrToIPv6(addr.inet.ip, &ipv6);
        }
        else if (addr.raw.family == PR_AF_INET6) {
            // copy the address
            memcpy(&ipv6, &addr.ipv6.ip, sizeof(SOCKS5SocketPRIPv6Addr));
        }
        else {
            NS_WARNING("unknown address family");
            return PR_TRUE; // allow proxying
        }
    }
    // Don't use proxy for local hosts (plain hostname, no dots)
    if (!is_ipaddr && mFilterLocalHosts && (kNotFound == host.FindChar('.'))) {
        LOG(("Not using proxy for this local host [%s]!\n", host.get()));
        return PR_FALSE; // don't allow proxying
    }
    int32_t index = -1;
    while (++index < int32_t(mHostFiltersArray.Length())) {
        HostInfo *hinfo = mHostFiltersArray[index];

        if (is_ipaddr != hinfo->is_ipaddr)
            continue;
        if (hinfo->port && hinfo->port != port)
            continue;

        if (is_ipaddr) {
            // generate masked version of target IPv6 address
            SOCKS5SocketPRIPv6Addr masked;
            memcpy(&masked, &ipv6, sizeof(SOCKS5SocketPRIPv6Addr));
            proxy_MaskIPv6Addr(&masked, hinfo->ip.mask_len);

            // check for a match
            if (memcmp(&masked, &hinfo->ip.addr, sizeof(SOCKS5SocketPRIPv6Addr)) == 0)
                return PR_FALSE; // proxy disallowed
        }
        else {
            uint32_t host_len = host.Length();
            uint32_t filter_host_len = hinfo->name.host_len;

            if (host_len >= filter_host_len) {
                //
                // compare last |filter_host_len| bytes of target hostname.
                //
                const char *host_tail = host.get() + host_len - filter_host_len;
                if (!PL_strncasecmp(host_tail, hinfo->name.host, filter_host_len))
                    return PR_FALSE; // proxy disallowed
            }
        }
    }
    return PR_TRUE;
#endif

typedef struct SOCKS5SocketPRIPv6AddrStr {
        union {
                PRUint8  _S6_u8[16];
                PRUint16 _S6_u16[8];
                PRUint32 _S6_u32[4];
                PRUint64 _S6_u64[2];
        } _S6_un;
} SOCKS5SocketPRIPv6Addr;

#define pr_s6_addr      _S6_un._S6_u8
#define pr_s6_addr16    _S6_un._S6_u16
#define pr_s6_addr32    _S6_un._S6_u32
#define pr_s6_addr64    _S6_un._S6_u64

typedef union SOCKS5SocketIPv6AddrStr {
  uint8_t  u8[16];
  uint16_t u16[8];
  uint32_t u32[4];
  uint64_t u64[2];
} SOCKS5SocketIPv6Addr;

typedef union SOCKS5SocketNetAddrStr {
  struct {
    uint16_t family;                /* address family (0x00ff maskable) */
    char data[14];                  /* raw address data */
  } raw;
  struct {
    uint16_t family;                /* address family (AF_INET) */
    uint16_t port;                  /* port number */
    uint32_t ip;                    /* The actual 32 bits of address */
  } inet;
  struct {
    uint16_t family;                /* address family (AF_INET6) */
    uint16_t port;                  /* port number */
    uint32_t flowinfo;              /* routing information */
    SOCKS5SocketIPv6Addr ip;                    /* the actual 128 bits of address */
    uint32_t scope_id;              /* set of interfaces for a scope */
  } inet6;
#if defined(XP_UNIX) || defined(XP_OS2)
  struct {                          /* Unix domain socket address */
    uint16_t family;                /* address family (AF_UNIX) */
#ifdef XP_OS2
    char path[108];                 /* null-terminated pathname */
#else
    char path[104];                 /* null-terminated pathname */
#endif
  } local;
#endif
} SOCKS5SocketNetAddr;

/*
static void
proxy_MaskIPv6Addr(SOCKS5SocketPRIPv6Addr *addr, uint16_t mask_len)
{
    if (mask_len == 128)
        return;

    if (mask_len > 96) {
        addr->pr_s6_addr32[3] = PR_htonl(
                PR_ntohl(addr->pr_s6_addr32[3]) & (~0L << (128 - mask_len)));
    }
    else if (mask_len > 64) {
        addr->pr_s6_addr32[3] = 0;
        addr->pr_s6_addr32[2] = PR_htonl(
                PR_ntohl(addr->pr_s6_addr32[2]) & (~0L << (96 - mask_len)));
    }
    else if (mask_len > 32) {
        addr->pr_s6_addr32[3] = 0;
        addr->pr_s6_addr32[2] = 0;
        addr->pr_s6_addr32[1] = PR_htonl(
                PR_ntohl(addr->pr_s6_addr32[1]) & (~0L << (64 - mask_len)));
    }
    else {
        addr->pr_s6_addr32[3] = 0;
        addr->pr_s6_addr32[2] = 0;
        addr->pr_s6_addr32[1] = 0;
        addr->pr_s6_addr32[0] = PR_htonl(
                PR_ntohl(addr->pr_s6_addr32[0]) & (~0L << (32 - mask_len)));
    }
}
*/

typedef enum SOCKS5SocketInfoState_Enum {
    SOCKS_INITIAL,
    SOCKS_CONNECTING_TO_PROXY,
    SOCKS5_WRITE_AUTH_REQUEST,
    SOCKS5_READ_AUTH_RESPONSE,
    SOCKS5_WRITE_CONNECT_REQUEST,
    SOCKS5_READ_CONNECT_RESPONSE_TOP,
    SOCKS5_READ_CONNECT_RESPONSE_BOTTOM,
    SOCKS_CONNECTED,
    SOCKS_FAILED
} SOCKS5SocketInfoStateEnum;

typedef struct SOCKS5SocketInfoStr
{
    SOCKS5SocketInfoStateEnum     mState;
    uint8_t * mData;
    uint8_t * mDataIoPtr;
    uint32_t  mDataLength;
    uint32_t  mReadOffset;
    uint32_t  mAmountToRead;
    PRFileDesc *mFD;

    char* mDestinationHost;
    int32_t mDestinationPort;
    int32_t   mVersion;   // SOCKS version 4 or 5
    int32_t   mDestinationFamily;
    SOCKS5SocketNetAddr   mInternalProxyAddr;
    SOCKS5SocketNetAddr   mExternalProxyAddr;
    SOCKS5SocketNetAddr   mDestinationAddr;
    PRIntervalTime mTimeout;
} SOCKS5SocketInfo;

// Copies the contents of a SOCKS5SocketNetAddr to a PRNetAddr.
// Does not do a ptr safety check!
static void SOCKS5Socket_NetAddrToPRNetAddr(const SOCKS5SocketNetAddr *addr, PRNetAddr *prAddr)
{
  if (addr->raw.family == AF_INET) {
    prAddr->inet.family = PR_AF_INET;
    prAddr->inet.port = addr->inet.port;
    prAddr->inet.ip = addr->inet.ip;
  }
  else if (addr->raw.family == AF_INET6) {
    prAddr->ipv6.family = PR_AF_INET6;
    prAddr->ipv6.port = addr->inet6.port;
    prAddr->ipv6.flowinfo = addr->inet6.flowinfo;
    memcpy(&prAddr->ipv6.ip, &addr->inet6.ip, sizeof(addr->inet6.ip.u8));
    prAddr->ipv6.scope_id = addr->inet6.scope_id;
  }
#if defined(XP_UNIX) || defined(XP_OS2)
  else if (addr->raw.family == AF_LOCAL) {
    prAddr->local.family = PR_AF_LOCAL;
    memcpy(prAddr->local.path, addr->local.path, sizeof(addr->local.path));
  }
#endif
}

static void SOCKS5Socket_PRNetAddrToNetAddr(const PRNetAddr *prAddr, SOCKS5SocketNetAddr *addr)
{
  if (prAddr->inet.family == PR_AF_INET) {
    addr->raw.family = AF_INET;
    addr->inet.port = prAddr->inet.port;
    addr->inet.ip = prAddr->inet.ip;
  }
  else if (prAddr->ipv6.family == PR_AF_INET6) {
    addr->raw.family = AF_INET6;
    addr->inet6.port = prAddr->ipv6.port;
    addr->inet6.flowinfo = prAddr->ipv6.flowinfo;
    memcpy(&addr->inet6.ip, &prAddr->ipv6.ip, sizeof(addr->inet6.ip.u8));
    addr->inet6.scope_id = prAddr->ipv6.scope_id;
  }
#if defined(XP_UNIX) || defined(XP_OS2)
  else if (prAddr->local.family == PR_AF_LOCAL) {
    addr->raw.family = AF_LOCAL;
    memcpy(addr->local.path, prAddr->local.path, sizeof(addr->local.path));
  }
#endif
}

static SOCKS5SocketInfo *
SOCKS5SocketInfo_create(int32_t family, const char *proxyHost, int32_t proxyPort, const char *host, int32_t port)
{
    SOCKS5SocketInfo *obj;
    PRBool is_ipaddr;
    PRNetAddr proxyAddr;

    if (strlen(host) > MAX_HOSTNAME_LEN) {
        return NULL;
    }

    is_ipaddr = (PR_StringToNetAddr(proxyHost, &proxyAddr) == PR_SUCCESS);
    if (!is_ipaddr) {
        return NULL;
    }

    obj = PORT_New(SOCKS5SocketInfo);
    if (!obj)
        return NULL;

    proxyAddr.inet.port = PR_htons(proxyPort);
    SOCKS5Socket_PRNetAddrToNetAddr(&proxyAddr, &obj->mInternalProxyAddr);

    obj->mDestinationHost = PORT_Strdup(host);
    obj->mData = PORT_Alloc(BUFFER_SIZE);

    if (!obj->mDestinationHost || !obj->mData) {
        if (obj->mDestinationHost)
            PORT_Free(obj->mDestinationHost);
        if (obj->mData)
            PORT_Free(obj->mData);
        PORT_Free(obj);
        return NULL;
    }
    
    obj->mState = SOCKS_INITIAL;
    obj->mDataIoPtr = NULL;
    obj->mDataLength = 0;
    obj->mReadOffset = 0;
    obj->mAmountToRead = 0;
    obj->mVersion = -1;
    obj->mDestinationFamily = AF_INET;
    obj->mTimeout = PR_INTERVAL_NO_TIMEOUT;
    obj->mVersion         = 5;
    obj->mDestinationPort = htons(port);
    obj->mDestinationFamily = family;
    obj->mExternalProxyAddr.raw.family = AF_INET;
    obj->mExternalProxyAddr.inet.ip = htonl(INADDR_ANY);
    obj->mExternalProxyAddr.inet.port = htons(0);
    obj->mDestinationAddr.raw.family = AF_INET;
    obj->mDestinationAddr.inet.ip = htonl(INADDR_ANY);
    obj->mDestinationAddr.inet.port = htons(0);
    return obj;
}

static void
SOCKS5SocketInfo_HandshakeFinished(SOCKS5SocketInfo *obj, PRErrorCode err)
{
    if (err == 0) {
        obj->mState = SOCKS_CONNECTED;
    } else {
        obj->mState = SOCKS_FAILED;
        PR_SetError(PR_UNKNOWN_ERROR, err);
    }

    // We don't need the buffer any longer, so free it.
    PORT_Free(obj->mData);
    obj->mData = NULL;
    obj->mDataIoPtr = NULL;
    obj->mDataLength = 0;
    obj->mReadOffset = 0;
    obj->mAmountToRead = 0;
}

static void
SOCKS5SocketInfo_FixupAddressFamily(SOCKS5SocketInfo *obj, PRFileDesc *fd, SOCKS5SocketNetAddr *proxy)
{
    PROsfd osfd;
    PRFileDesc *tmpfd;
    PROsfd newsd;
    int32_t proxyFamily = obj->mInternalProxyAddr.raw.family;
    // Do nothing if the address family is already matched
    if (proxyFamily == obj->mDestinationFamily) {
        return;
    }
    // If the system does not support IPv6 and the proxy address is IPv6,
    // We can do nothing here.
    if (proxyFamily == AF_INET6 && !ipv6Supported) {
        return;
    }
    // If the system does not support IPv6 and the destination address is
    // IPv6, convert IPv4 address to IPv4-mapped IPv6 address to satisfy
    // the emulation layer
    if (obj->mDestinationFamily == AF_INET6 && !ipv6Supported) {
        uint8_t *proxyp;
        proxy->inet6.family = AF_INET6;
        proxy->inet6.port = obj->mInternalProxyAddr.inet.port;
        proxyp = proxy->inet6.ip.u8;
        memset(proxyp, 0, 10);
        memset(proxyp + 10, 0xff, 2);
        memcpy(proxyp + 12,(char *) &obj->mInternalProxyAddr.inet.ip, 4);
        // mDestinationFamily should not be updated
        return;
    }
    // Get an OS native handle from a specified FileDesc
    osfd = PR_FileDesc2NativeHandle(fd);
    if (osfd == -1) {
        return;
    }
    // Create a new FileDesc with a specified family
    tmpfd = PR_OpenTCPSocket(proxyFamily);
    if (!tmpfd) {
        return;
    }
    newsd = PR_FileDesc2NativeHandle(tmpfd);
    if (newsd == -1) {
        PR_Close(tmpfd);
        return;
    }
    // Must succeed because PR_FileDesc2NativeHandle succeeded
    fd = PR_GetIdentitiesLayer(fd, PR_NSPR_IO_LAYER);
    PORT_Assert(fd);
    // Swap OS native handles
    PR_ChangeFileDescNativeHandle(fd, newsd);
    PR_ChangeFileDescNativeHandle(tmpfd, osfd);
    // Close temporary FileDesc which is now associated with
    // old OS native handle
    PR_Close(tmpfd);
    obj->mDestinationFamily = proxyFamily;
}

static const char *inet_ntop_internal(int af, const void *src, char *dst, socklen_t size)
{
#ifdef XP_WIN
  if (af == AF_INET) {
    struct sockaddr_in s;
    memset(&s, 0, sizeof(s));
    s.sin_family = AF_INET;
    memcpy(&s.sin_addr, src, sizeof(struct in_addr));
    int result = getnameinfo((struct sockaddr *)&s, sizeof(struct sockaddr_in),
                             dst, size, nullptr, 0, NI_NUMERICHOST);
    if (result == 0) {
      return dst;
    }
  }
  else if (af == AF_INET6) {
    struct sockaddr_in6 s;
    memset(&s, 0, sizeof(s));
    s.sin6_family = AF_INET6;
    memcpy(&s.sin6_addr, src, sizeof(struct in_addr6));
    int result = getnameinfo((struct sockaddr *)&s, sizeof(struct sockaddr_in6),
                             dst, size, nullptr, 0, NI_NUMERICHOST);
    if (result == 0) {
      return dst;
    }
  }
  return NULL;
#else
  return inet_ntop(af, src, dst, size);
#endif
}

static PRBool SOCKS5Socket_NetAddrToString(const SOCKS5SocketNetAddr *addr, char *buf, uint32_t bufSize)
{
  if (addr->raw.family == AF_INET) {
    struct in_addr nativeAddr = {};
    if (bufSize < INET_ADDRSTRLEN) {
      return PR_FALSE;
    }
    nativeAddr.s_addr = addr->inet.ip;
    return !!inet_ntop_internal(AF_INET, &nativeAddr, buf, bufSize);
  }
  else if (addr->raw.family == AF_INET6) {
    struct in6_addr nativeAddr = {};
    if (bufSize < INET6_ADDRSTRLEN) {
      return PR_FALSE;
    }
    memcpy(&nativeAddr.s6_addr, &addr->inet6.ip, sizeof(addr->inet6.ip.u8));
    return !!inet_ntop_internal(AF_INET6, &nativeAddr, buf, bufSize);
  }
#if defined(XP_UNIX) || defined(XP_OS2)
  else if (addr->raw.family == AF_LOCAL) {
    if (bufSize < sizeof(addr->local.path)) {
      return PR_FALSE;
    }
    memcpy(buf, addr->local.path, bufSize);
    return PR_TRUE;
  }
#endif
  return PR_FALSE;
}

#define NS_ABORT_IF_FALSE(exp, msg) PORT_Assert(exp)

inline void
SOCKS5SocketInfo_WriteUint8(SOCKS5SocketInfo *obj, uint8_t v)
{
    NS_ABORT_IF_FALSE(obj->mDataLength + sizeof(v) <= BUFFER_SIZE,
                      "Can't write that much data!");
    obj->mData[obj->mDataLength] = v;
    obj->mDataLength += sizeof(v);
}

inline void
SOCKS5SocketInfo_WriteUint16(SOCKS5SocketInfo *obj, uint16_t v)
{
    NS_ABORT_IF_FALSE(obj->mDataLength + sizeof(v) <= BUFFER_SIZE,
                      "Can't write that much data!");
    memcpy(obj->mData + obj->mDataLength, &v, sizeof(v));
    obj->mDataLength += sizeof(v);
}

inline void
SOCKS5SocketInfo_WriteUint32(SOCKS5SocketInfo *obj, uint32_t v)
{
    NS_ABORT_IF_FALSE(obj->mDataLength + sizeof(v) <= BUFFER_SIZE,
                      "Can't write that much data!");
    memcpy(obj->mData + obj->mDataLength, &v, sizeof(v));
    obj->mDataLength += sizeof(v);
}

static void
SOCKS5SocketInfo_WriteNetAddr(SOCKS5SocketInfo *obj, const SOCKS5SocketNetAddr *addr)
{
    const char *ip = NULL;
    uint32_t len = 0;

    if (addr->raw.family == AF_INET) {
        ip = (const char*)&addr->inet.ip;
        len = sizeof(addr->inet.ip);
    } else if (addr->raw.family == AF_INET6) {
        ip = (const char*)addr->inet6.ip.u8;
        len = sizeof(addr->inet6.ip.u8);
    }

    NS_ABORT_IF_FALSE(ip != NULL, "Unknown address");
    NS_ABORT_IF_FALSE(obj->mDataLength + len <= BUFFER_SIZE,
                      "Can't write that much data!");
 
    memcpy(obj->mData + obj->mDataLength, ip, len);
    obj->mDataLength += len;
}

static void
SOCKS5SocketInfo_WriteString(SOCKS5SocketInfo *obj, const char *str)
{
    size_t len = strlen(str);
    NS_ABORT_IF_FALSE(obj->mDataLength + len <= BUFFER_SIZE,
                      "Can't write that much data!");
    memcpy(obj->mData + obj->mDataLength, str, len);
    obj->mDataLength += len;
}

inline uint8_t
SOCKS5SocketInfo_ReadUint8(SOCKS5SocketInfo *obj)
{
    uint8_t rv;
    NS_ABORT_IF_FALSE(obj->mReadOffset + sizeof(rv) <= obj->mDataLength,
                      "Not enough space to pop a uint8_t!");
    rv = obj->mData[obj->mReadOffset];
    obj->mReadOffset += sizeof(rv);
    return rv;
}

inline uint16_t
SOCKS5SocketInfo_ReadUint16(SOCKS5SocketInfo *obj)
{
    uint16_t rv;
    NS_ABORT_IF_FALSE(obj->mReadOffset + sizeof(rv) <= obj->mDataLength,
                      "Not enough space to pop a uint16_t!");
    memcpy(&rv, obj->mData + obj->mReadOffset, sizeof(rv));
    obj->mReadOffset += sizeof(rv);
    return rv;
}

inline uint32_t
SOCKS5SocketInfo_ReadUint32(SOCKS5SocketInfo *obj)
{
    uint32_t rv;
    NS_ABORT_IF_FALSE(obj->mReadOffset + sizeof(rv) <= obj->mDataLength,
                      "Not enough space to pop a uint32_t!");
    memcpy(&rv, obj->mData + obj->mReadOffset, sizeof(rv));
    obj->mReadOffset += sizeof(rv);
    return rv;
}

static void
SOCKS5SocketInfo_ReadNetAddr(SOCKS5SocketInfo *obj, SOCKS5SocketNetAddr *addr, uint16_t fam)
{
    uint32_t amt = 0;
    const uint8_t *ip = obj->mData + obj->mReadOffset;

    addr->raw.family = fam;
    if (fam == AF_INET) {
        amt = sizeof(addr->inet.ip);
        NS_ABORT_IF_FALSE(obj->mReadOffset + amt <= obj->mDataLength,
                          "Not enough space to pop an ipv4 addr!");
        memcpy(&addr->inet.ip, ip, amt);
    } else if (fam == AF_INET6) {
        amt = sizeof(addr->inet6.ip.u8);
        NS_ABORT_IF_FALSE(obj->mReadOffset + amt <= obj->mDataLength,
                          "Not enough space to pop an ipv6 addr!");
        memcpy(addr->inet6.ip.u8, ip, amt);
    }

    obj->mReadOffset += amt;
}

static void
SOCKS5SocketInfo_ReadNetPort(SOCKS5SocketInfo *obj, SOCKS5SocketNetAddr *addr)
{
    addr->inet.port = SOCKS5SocketInfo_ReadUint16(obj);
}

static void
SOCKS5SocketInfo_WantRead(SOCKS5SocketInfo *obj, uint32_t sz)
{
    NS_ABORT_IF_FALSE(obj->mDataIoPtr == NULL,
                      "WantRead() called while I/O already in progress!");
    NS_ABORT_IF_FALSE(obj->mDataLength + sz <= BUFFER_SIZE,
                      "Can't read that much data!");
    obj->mAmountToRead = sz;
}

static PRStatus
SOCKS5SocketInfo_WriteV5AuthRequest(SOCKS5SocketInfo *obj)
{
    PORT_Assert(obj->mVersion == 5);

    obj->mState = SOCKS5_WRITE_AUTH_REQUEST;

    // Send an initial SOCKS 5 greeting
    LOGDEBUG(("socks5: sending auth methods"));
    SOCKS5SocketInfo_WriteUint8(obj, 0x05); // version -- 5
    SOCKS5SocketInfo_WriteUint8(obj, 0x01); // # auth methods -- 1
    SOCKS5SocketInfo_WriteUint8(obj, 0x00); // we don't support authentication

    return PR_SUCCESS;
}

static PRStatus
SOCKS5SocketInfo_ConnectToProxy(SOCKS5SocketInfo *obj, PRFileDesc *fd)
{
    PRStatus status;

    do {
#if defined(PR_LOGGING)
        char buf[kIPv6CStrBufSize];
#endif
        SOCKS5SocketNetAddr proxy;
        PRNetAddr prProxy;

#if defined(PR_LOGGING)
        SOCKS5Socket_NetAddrToString(&obj->mInternalProxyAddr, buf, sizeof(buf));
        LOGDEBUG(("socks: trying proxy server, %s:%hu",
                 buf, ntohs(obj->mInternalProxyAddr.inet.port)));
#endif
        proxy = obj->mInternalProxyAddr;
        SOCKS5SocketInfo_FixupAddressFamily(obj, fd, &proxy);
        SOCKS5Socket_NetAddrToPRNetAddr(&proxy, &prProxy);
        status = fd->lower->methods->connect(fd->lower, &prProxy, obj->mTimeout);
        if (status != PR_SUCCESS) {
            PRErrorCode c = PR_GetError();
            // If EINPROGRESS, return now and check back later after polling
            if (c == PR_WOULD_BLOCK_ERROR || c == PR_IN_PROGRESS_ERROR) {
                obj->mState = SOCKS_CONNECTING_TO_PROXY;
                return status;
            }
        }
    } while (status != PR_SUCCESS);

    // Connected now, start SOCKS
    return SOCKS5SocketInfo_WriteV5AuthRequest(obj);
}

static PRStatus
SOCKS5SocketInfo_ContinueConnectingToProxy(SOCKS5SocketInfo *obj, PRFileDesc *fd, int16_t oflags)
{
    PRStatus status;

    NS_ABORT_IF_FALSE(obj->mState == SOCKS_CONNECTING_TO_PROXY,
                      "Continuing connection in wrong state!");

    LOGDEBUG(("socks: continuing connection to proxy"));

    status = fd->lower->methods->connectcontinue(fd->lower, oflags);
    if (status != PR_SUCCESS) {
        LOGDEBUG(("socks: continuing connection to proxy: non-success"));
        PRErrorCode c = PR_GetError();
        if (c != PR_WOULD_BLOCK_ERROR && c != PR_IN_PROGRESS_ERROR) {
            LOGDEBUG(("socks: continuing connection to proxy: error: %d", c));
            // A connection failure occured, try another address
            obj->mState = SOCKS_FAILED;
            SOCKS5SocketInfo_HandshakeFinished(obj, c);
            return PR_FAILURE;
        }

        LOGDEBUG(("socks: continuing connection to proxy: still connecting"));
        // We're still connecting
        return PR_FAILURE;
    }

    LOGDEBUG(("socks: continuing connection to proxy: connected now"));
    // Connected now, start SOCKS
    return SOCKS5SocketInfo_WriteV5AuthRequest(obj);
}

static PRStatus
SOCKS5SocketInfo_WriteV5ConnectRequest(SOCKS5SocketInfo *obj)
{
    PRBool is_ipaddr;
    // Send SOCKS 5 connect request
    SOCKS5SocketNetAddr *addr = &obj->mDestinationAddr;
    PRNetAddr prAddr;

    obj->mDataLength = 0;
    obj->mState = SOCKS5_WRITE_CONNECT_REQUEST;

    SOCKS5SocketInfo_WriteUint8(obj, 0x05); // version -- 5
    SOCKS5SocketInfo_WriteUint8(obj, 0x01); // command -- connect
    SOCKS5SocketInfo_WriteUint8(obj, 0x00); // reserved

    is_ipaddr = (PR_StringToNetAddr(obj->mDestinationHost, &prAddr) == PR_SUCCESS);
    if (!is_ipaddr) {
        /*already checked on construction
        // Add the host name. Only a single byte is used to store the length,
        // so we must prevent long names from being used.
        if (obj->mDestinationHost.Length() > MAX_HOSTNAME_LEN) {
            LOGERROR(("socks5: destination host name is too long!"));
            SOCKS5SocketInfo_HandshakeFinished(obj, PR_BAD_ADDRESS_ERROR);
            return PR_FAILURE;
        }
        */
        SOCKS5SocketInfo_WriteUint8(obj, 0x03); // addr type -- domainname
        SOCKS5SocketInfo_WriteUint8(obj, strlen(obj->mDestinationHost)); // name length
        SOCKS5SocketInfo_WriteString(obj, obj->mDestinationHost);
    } else if (addr->raw.family == AF_INET) {
        SOCKS5SocketInfo_WriteUint8(obj, 0x01); // addr type -- IPv4
        SOCKS5SocketInfo_WriteNetAddr(obj, addr);
    } else if (addr->raw.family == AF_INET6) {
        SOCKS5SocketInfo_WriteUint8(obj, 0x04); // addr type -- IPv6
        SOCKS5SocketInfo_WriteNetAddr(obj, addr);
    } else {
        LOGERROR(("socks5: destination address of unknown type!"));
        SOCKS5SocketInfo_HandshakeFinished(obj, PR_BAD_ADDRESS_ERROR);
        return PR_FAILURE;
    }

    SOCKS5SocketInfo_WriteUint16(obj, obj->mDestinationPort);

    return PR_SUCCESS;
}

static PRStatus
SOCKS5SocketInfo_ReadV5AuthResponse(SOCKS5SocketInfo *obj)
{
    NS_ABORT_IF_FALSE(obj->mState == SOCKS5_READ_AUTH_RESPONSE,
                      "Handling SOCKS 5 auth method reply in wrong state!");
    NS_ABORT_IF_FALSE(obj->mDataLength == 2,
                      "SOCKS 5 auth method reply must be 2 bytes!");

    LOGDEBUG(("socks5: checking auth method reply"));

    // Check version number
    if (SOCKS5SocketInfo_ReadUint8(obj) != 0x05) {
        LOGERROR(("socks5: unexpected version in the reply"));
        SOCKS5SocketInfo_HandshakeFinished(obj, PR_CONNECT_REFUSED_ERROR);
        return PR_FAILURE;
    }

    // Make sure our authentication choice was accepted
    if (SOCKS5SocketInfo_ReadUint8(obj) != 0x00) {
        LOGERROR(("socks5: server did not accept our authentication method"));
        SOCKS5SocketInfo_HandshakeFinished(obj, PR_CONNECT_REFUSED_ERROR);
        return PR_FAILURE;
    }

    return SOCKS5SocketInfo_WriteV5ConnectRequest(obj);
}

static PRStatus
SOCKS5SocketInfo_ReadV5AddrTypeAndLength(SOCKS5SocketInfo *obj, uint8_t *type, uint32_t *len)
{
    NS_ABORT_IF_FALSE(obj->mState == SOCKS5_READ_CONNECT_RESPONSE_TOP ||
                      obj->mState == SOCKS5_READ_CONNECT_RESPONSE_BOTTOM,
                      "Invalid state!");
    NS_ABORT_IF_FALSE(obj->mDataLength >= 5,
                      "SOCKS 5 connection reply must be at least 5 bytes!");
 
    // Seek to the address location 
    obj->mReadOffset = 3;
   
    *type = SOCKS5SocketInfo_ReadUint8(obj);

    switch (*type) {
        case 0x01: // ipv4
            *len = 4 - 1;
            break;
        case 0x04: // ipv6
            *len = 16 - 1;
            break;
        case 0x03: // fqdn
            *len = SOCKS5SocketInfo_ReadUint8(obj);
            break;
        default:   // wrong address type
            LOGERROR(("socks5: wrong address type in connection reply!"));
            return PR_FAILURE;
    }

    return PR_SUCCESS;
}

static PRStatus
SOCKS5SocketInfo_ReadV5ConnectResponseTop(SOCKS5SocketInfo *obj)
{
    uint8_t res;
    uint32_t len;

    NS_ABORT_IF_FALSE(obj->mState == SOCKS5_READ_CONNECT_RESPONSE_TOP,
                      "Invalid state!");
    NS_ABORT_IF_FALSE(obj->mDataLength == 5,
                      "SOCKS 5 connection reply must be exactly 5 bytes!");

    LOGDEBUG(("socks5: checking connection reply"));

    // Check version number
    if (SOCKS5SocketInfo_ReadUint8(obj) != 0x05) {
        LOGERROR(("socks5: unexpected version in the reply"));
        SOCKS5SocketInfo_HandshakeFinished(obj, PR_CONNECT_REFUSED_ERROR);
        return PR_FAILURE;
    }

    // Check response
    res = SOCKS5SocketInfo_ReadUint8(obj);
    if (res != 0x00) {
        PRErrorCode c = PR_CONNECT_REFUSED_ERROR;

        switch (res) {
            case 0x01:
                LOGERROR(("socks5: connect failed: "
                          "01, General SOCKS server failure."));
                break;
            case 0x02:
                LOGERROR(("socks5: connect failed: "
                          "02, Connection not allowed by ruleset."));
                break;
            case 0x03:
                LOGERROR(("socks5: connect failed: 03, Network unreachable."));
                c = PR_NETWORK_UNREACHABLE_ERROR;
                break;
            case 0x04:
                LOGERROR(("socks5: connect failed: 04, Host unreachable."));
                break;
            case 0x05:
                LOGERROR(("socks5: connect failed: 05, Connection refused."));
                break;
            case 0x06:  
                LOGERROR(("socks5: connect failed: 06, TTL expired."));
                c = PR_CONNECT_TIMEOUT_ERROR;
                break;
            case 0x07:
                LOGERROR(("socks5: connect failed: "
                          "07, Command not supported."));
                break;
            case 0x08:
                LOGERROR(("socks5: connect failed: "
                          "08, Address type not supported."));
                c = PR_BAD_ADDRESS_ERROR;
                break;
            default:
                LOGERROR(("socks5: connect failed."));
                break;
        }

        SOCKS5SocketInfo_HandshakeFinished(obj, c);
        return PR_FAILURE;
    }

    if (SOCKS5SocketInfo_ReadV5AddrTypeAndLength(obj, &res, &len) != PR_SUCCESS) {
        SOCKS5SocketInfo_HandshakeFinished(obj, PR_BAD_ADDRESS_ERROR);
        return PR_FAILURE;
    }

    obj->mState = SOCKS5_READ_CONNECT_RESPONSE_BOTTOM;
    SOCKS5SocketInfo_WantRead(obj, len + 2);

    return PR_SUCCESS;
}

static PRStatus
SOCKS5SocketInfo_ReadV5ConnectResponseBottom(SOCKS5SocketInfo *obj)
{
    uint8_t type;
    uint32_t len;

    NS_ABORT_IF_FALSE(obj->mState == SOCKS5_READ_CONNECT_RESPONSE_BOTTOM,
                      "Invalid state!");

    if (SOCKS5SocketInfo_ReadV5AddrTypeAndLength(obj, &type, &len) != PR_SUCCESS) {
        SOCKS5SocketInfo_HandshakeFinished(obj, PR_BAD_ADDRESS_ERROR);
        return PR_FAILURE;
    }

    NS_ABORT_IF_FALSE(obj->mDataLength == 7+len,
                      "SOCKS 5 unexpected length of connection reply!");

    LOGDEBUG(("socks5: loading source addr and port"));
    // Read what the proxy says is our source address
    switch (type) {
        case 0x01: // ipv4
            SOCKS5SocketInfo_ReadNetAddr(obj, &obj->mExternalProxyAddr, AF_INET);
            break;
        case 0x04: // ipv6
            SOCKS5SocketInfo_ReadNetAddr(obj, &obj->mExternalProxyAddr, AF_INET6);
            break;
        case 0x03: // fqdn (skip)
            obj->mReadOffset += len;
            obj->mExternalProxyAddr.raw.family = AF_INET;
            break;
    }

    SOCKS5SocketInfo_ReadNetPort(obj, &obj->mExternalProxyAddr);

    LOGDEBUG(("socks5: connected!"));
    SOCKS5SocketInfo_HandshakeFinished(obj, 0);

    return PR_SUCCESS;
}

static int16_t
SOCKS5SocketInfo_GetPollFlags(SOCKS5SocketInfo *obj)
{
    switch (obj->mState) {
        case SOCKS_CONNECTING_TO_PROXY:
            return PR_POLL_EXCEPT | PR_POLL_WRITE;
        case SOCKS5_WRITE_AUTH_REQUEST:
        case SOCKS5_WRITE_CONNECT_REQUEST:
            return PR_POLL_WRITE;
        case SOCKS5_READ_AUTH_RESPONSE:
        case SOCKS5_READ_CONNECT_RESPONSE_TOP:
        case SOCKS5_READ_CONNECT_RESPONSE_BOTTOM:
            return PR_POLL_READ;
        default:
            break;
    }

    return 0;
}

static PRStatus
SOCKS5SocketInfo_ReadFromSocket(SOCKS5SocketInfo *obj, PRFileDesc *fd)
{
    int32_t rc;
    const uint8_t *end;

    if (!obj->mAmountToRead) {
        LOGDEBUG(("socks: ReadFromSocket(), nothing to do"));
        return PR_SUCCESS;
    }

    if (!obj->mDataIoPtr) {
        obj->mDataIoPtr = obj->mData + obj->mDataLength;
        obj->mDataLength += obj->mAmountToRead;
    }

    end = obj->mData + obj->mDataLength;

    while (obj->mDataIoPtr < end) {
        rc = PR_Read(fd, obj->mDataIoPtr, end - obj->mDataIoPtr);
        if (rc <= 0) {
            if (rc == 0) {
                LOGERROR(("socks: proxy server closed connection"));
                SOCKS5SocketInfo_HandshakeFinished(obj, PR_CONNECT_REFUSED_ERROR);
                return PR_FAILURE;
            } else if (PR_GetError() == PR_WOULD_BLOCK_ERROR) {
                LOGDEBUG(("socks: ReadFromSocket(), want read"));
            }
            break;
        }

        obj->mDataIoPtr += rc;
    }

    LOGDEBUG(("socks: ReadFromSocket(), have %u bytes total",
             (unsigned)(obj->mDataIoPtr - obj->mData)));
    if (obj->mDataIoPtr == end) {
        obj->mDataIoPtr = NULL;
        obj->mAmountToRead = 0;
        obj->mReadOffset = 0;
        return PR_SUCCESS;
    }

    return PR_FAILURE;
}

static PRStatus
SOCKS5SocketInfo_WriteToSocket(SOCKS5SocketInfo *obj, PRFileDesc *fd)
{
    int32_t rc;
    const uint8_t *end;

    if (!obj->mDataLength) {
        LOGDEBUG(("socks: WriteToSocket(), nothing to do"));
        return PR_SUCCESS;
    }

    if (!obj->mDataIoPtr)
        obj->mDataIoPtr = obj->mData;

    end = obj->mData + obj->mDataLength;

    while (obj->mDataIoPtr < end) {
        rc = PR_Write(fd, obj->mDataIoPtr, end - obj->mDataIoPtr);
        if (rc < 0) {
            if (PR_GetError() == PR_WOULD_BLOCK_ERROR) {
                LOGDEBUG(("socks: WriteToSocket(), want write"));
            }
            break;
        }
        
        obj->mDataIoPtr += rc;
    }

    if (obj->mDataIoPtr == end) {
        obj->mDataIoPtr = NULL;
        obj->mDataLength = 0;
        obj->mReadOffset = 0;
        return PR_SUCCESS;
    }
    
    return PR_FAILURE;
}

static PRStatus
SOCKS5SocketInfo_DoHandshake(SOCKS5SocketInfo *obj, PRFileDesc *fd, int16_t oflags)
{
    LOGDEBUG(("socks: DoHandshake(), state = %d", obj->mState));

    switch (obj->mState) {
        case SOCKS_INITIAL:
            return SOCKS5SocketInfo_ConnectToProxy(obj, fd);
        case SOCKS_CONNECTING_TO_PROXY:
            return SOCKS5SocketInfo_ContinueConnectingToProxy(obj, fd, oflags);
        case SOCKS5_WRITE_AUTH_REQUEST:
            if (SOCKS5SocketInfo_WriteToSocket(obj, fd) != PR_SUCCESS)
                return PR_FAILURE;
            SOCKS5SocketInfo_WantRead(obj, 2);
            obj->mState = SOCKS5_READ_AUTH_RESPONSE;
            return PR_SUCCESS;
        case SOCKS5_READ_AUTH_RESPONSE:
            if (SOCKS5SocketInfo_ReadFromSocket(obj, fd) != PR_SUCCESS)
                return PR_FAILURE;
            return SOCKS5SocketInfo_ReadV5AuthResponse(obj);
        case SOCKS5_WRITE_CONNECT_REQUEST:
            if (SOCKS5SocketInfo_WriteToSocket(obj, fd) != PR_SUCCESS)
                return PR_FAILURE;

            // The SOCKS 5 response to the connection request is variable
            // length. First, we'll read enough to tell how long the response
            // is, and will read the rest later.
            SOCKS5SocketInfo_WantRead(obj, 5);
            obj->mState = SOCKS5_READ_CONNECT_RESPONSE_TOP;
            return PR_SUCCESS;
        case SOCKS5_READ_CONNECT_RESPONSE_TOP:
            if (SOCKS5SocketInfo_ReadFromSocket(obj, fd) != PR_SUCCESS)
                return PR_FAILURE;
            return SOCKS5SocketInfo_ReadV5ConnectResponseTop(obj);
        case SOCKS5_READ_CONNECT_RESPONSE_BOTTOM:
            if (SOCKS5SocketInfo_ReadFromSocket(obj, fd) != PR_SUCCESS)
                return PR_FAILURE;
            return SOCKS5SocketInfo_ReadV5ConnectResponseBottom(obj);

        case SOCKS_CONNECTED:
            LOGERROR(("socks: already connected"));
            SOCKS5SocketInfo_HandshakeFinished(obj, PR_IS_CONNECTED_ERROR);
            return PR_FAILURE;
        case SOCKS_FAILED:
            LOGERROR(("socks: already failed"));
            return PR_FAILURE;
    }

    LOGERROR(("socks: executing handshake in invalid state, %d", obj->mState));
    SOCKS5SocketInfo_HandshakeFinished(obj, PR_INVALID_STATE_ERROR);

    return PR_FAILURE;
}

static PRStatus
nsSOCKSIOLayerConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
    PRStatus status;
    SOCKS5SocketNetAddr dst;

    SOCKS5SocketInfo * info = (SOCKS5SocketInfo*) fd->secret;
    if (info == NULL) return PR_FAILURE;

    if (addr->raw.family == PR_AF_INET6 &&
        PR_IsNetAddrType(addr, PR_IpAddrV4Mapped)) {
        const uint8_t *srcp;

        LOGDEBUG(("socks: converting ipv4-mapped ipv6 address to ipv4"));

        // copied from _PR_ConvertToIpv4NetAddr()
        dst.raw.family = AF_INET;
        dst.inet.ip = htonl(INADDR_ANY);
        dst.inet.port = htons(0);
        srcp = addr->ipv6.ip.pr_s6_addr;
        memcpy(&dst.inet.ip, srcp + 12, 4);
        dst.inet.family = AF_INET;
        dst.inet.port = addr->ipv6.port;
    } else {
        memcpy(&dst, addr, sizeof(dst));
    }

    memcpy(&info->mDestinationAddr, &dst, sizeof(SOCKS5SocketNetAddr));
    info->mTimeout = to;

    do {
        status = SOCKS5SocketInfo_DoHandshake(info, fd, -1);
    } while (status == PR_SUCCESS && !(info->mState == SOCKS_CONNECTED));

    return status;
}

static PRStatus
nsSOCKSIOLayerConnectContinue(PRFileDesc *fd, int16_t oflags)
{
    PRStatus status;

    SOCKS5SocketInfo * info = (SOCKS5SocketInfo*) fd->secret;
    if (info == NULL) return PR_FAILURE;

    do { 
        status = SOCKS5SocketInfo_DoHandshake(info, fd, oflags);
    } while (status == PR_SUCCESS && !(info->mState == SOCKS_CONNECTED));

    return status;
}

static int16_t
nsSOCKSIOLayerPoll(PRFileDesc *fd, int16_t in_flags, int16_t *out_flags)
{
    SOCKS5SocketInfo * info = (SOCKS5SocketInfo*) fd->secret;
    if (info == NULL) return PR_FAILURE;

    if (!(info->mState == SOCKS_CONNECTED)) {
        *out_flags = 0;
        return SOCKS5SocketInfo_GetPollFlags(info);
    }

    return fd->lower->methods->poll(fd->lower, in_flags, out_flags);
}

static PRStatus
nsSOCKSIOLayerClose(PRFileDesc *fd)
{
    SOCKS5SocketInfo * info = (SOCKS5SocketInfo*) fd->secret;
    PRDescIdentity id = PR_GetLayersIdentity(fd);

    if (info && id == nsSOCKSIOLayerIdentity)
    {
        SOCKS5SocketInfo_HandshakeFinished(info, 0);
        PORT_Free(info);
        fd->identity = PR_INVALID_IO_LAYER;
    }

    return fd->lower->methods->close(fd->lower);
}

static PRFileDesc*
nsSOCKSIOLayerAccept(PRFileDesc *fd, PRNetAddr *addr, PRIntervalTime timeout)
{
    // TODO: implement SOCKS support for accept
    return fd->lower->methods->accept(fd->lower, addr, timeout);
}

static int32_t
nsSOCKSIOLayerAcceptRead(PRFileDesc *sd, PRFileDesc **nd, PRNetAddr **raddr, void *buf, int32_t amount, PRIntervalTime timeout)
{
    // TODO: implement SOCKS support for accept, then read from it
    return sd->lower->methods->acceptread(sd->lower, nd, raddr, buf, amount, timeout);
}

static PRStatus
nsSOCKSIOLayerBind(PRFileDesc *fd, const PRNetAddr *addr)
{
    // TODO: implement SOCKS support for bind (very similar to connect)
    return fd->lower->methods->bind(fd->lower, addr);
}

static PRStatus
nsSOCKSIOLayerGetName(PRFileDesc *fd, PRNetAddr *addr)
{
    SOCKS5SocketInfo * info = (SOCKS5SocketInfo*) fd->secret;
    
    if (info != NULL && addr != NULL) {
        SOCKS5Socket_NetAddrToPRNetAddr(&info->mExternalProxyAddr, addr);
        return PR_SUCCESS;
    }

    return PR_FAILURE;
}

static PRStatus
nsSOCKSIOLayerGetPeerName(PRFileDesc *fd, PRNetAddr *addr)
{
    SOCKS5SocketInfo * info = (SOCKS5SocketInfo*) fd->secret;

    if (info != NULL && addr != NULL) {
        SOCKS5Socket_NetAddrToPRNetAddr(&info->mDestinationAddr, addr);
        return PR_SUCCESS;
    }

    return PR_FAILURE;
}

static PRStatus
nsSOCKSIOLayerListen(PRFileDesc *fd, int backlog)
{
    // TODO: implement SOCKS support for listen
    return fd->lower->methods->listen(fd->lower, backlog);
}

// add SOCKS IO layer to an existing socket
static SECStatus
SOCKSIOLayerAddToSocket(int32_t family,
                          const char *host, 
                          int32_t port,
                          const char *proxyHost,
                          int32_t proxyPort,
                          PRFileDesc *fd)
{
    PRFileDesc *layer;
    PRStatus rv;
    SOCKS5SocketInfo * infoObject;

    if (firstTime)
    {
        //XXX hack until NSPR provides an official way to detect system IPv6
        // support (bug 388519)
        PRFileDesc *tmpfd = PR_OpenTCPSocket(PR_AF_INET6);
        if (!tmpfd) {
            ipv6Supported = PR_FALSE;
        } else {
            // If the system does not support IPv6, NSPR will push
            // IPv6-to-IPv4 emulation layer onto the native layer
            ipv6Supported = PR_GetIdentitiesLayer(tmpfd, PR_NSPR_IO_LAYER) == tmpfd;
            PR_Close(tmpfd);
        }

        nsSOCKSIOLayerIdentity = PR_GetUniqueIdentity("SSL-SOCKS5 layer");
        nsSOCKSIOLayerMethods = *PR_GetDefaultIOMethods();

        nsSOCKSIOLayerMethods.connect = nsSOCKSIOLayerConnect;
        nsSOCKSIOLayerMethods.connectcontinue = nsSOCKSIOLayerConnectContinue;
        nsSOCKSIOLayerMethods.poll = nsSOCKSIOLayerPoll;
        nsSOCKSIOLayerMethods.bind = nsSOCKSIOLayerBind;
        nsSOCKSIOLayerMethods.acceptread = nsSOCKSIOLayerAcceptRead;
        nsSOCKSIOLayerMethods.getsockname = nsSOCKSIOLayerGetName;
        nsSOCKSIOLayerMethods.getpeername = nsSOCKSIOLayerGetPeerName;
        nsSOCKSIOLayerMethods.accept = nsSOCKSIOLayerAccept;
        nsSOCKSIOLayerMethods.listen = nsSOCKSIOLayerListen;
        nsSOCKSIOLayerMethods.close = nsSOCKSIOLayerClose;

        firstTime = PR_FALSE;

#if defined(PR_LOGGING)
        gSOCKSLog = PR_NewLogModule("sslproxy");
#endif

    }

    LOGDEBUG(("Entering nsSOCKSIOLayerAddToSocket()."));


    layer = PR_CreateIOLayerStub(nsSOCKSIOLayerIdentity, &nsSOCKSIOLayerMethods);
    if (! layer)
    {
        LOGERROR(("PR_CreateIOLayerStub() failed."));
        return SECFailure;
    }

    infoObject = SOCKS5SocketInfo_create(family, proxyHost, proxyPort, host, port);
    if (!infoObject)
    {
        // clean up IOLayerStub
        LOGERROR(("Failed to create nsSOCKS5SocketInfo()."));
        PR_DELETE(layer);
        return SECFailure;
    }
    
    layer->secret = (PRFilePrivate*) infoObject;
    rv = PR_PushIOLayer(fd, PR_GetLayersIdentity(fd), layer);

    if (rv == PR_FAILURE) {
        LOGERROR(("PR_PushIOLayer() failed. rv = %x.", rv));
        SOCKS5SocketInfo_HandshakeFinished(infoObject, 0);
        PORT_Free(infoObject);
        PR_DELETE(layer);
        return SECFailure;
    }

    return SECSuccess;
}

SECStatus
SOCKS5Socket_New(int32_t family,
                                 const char *host, 
                                 int32_t port,
                                 const char *proxyHost,
                                 int32_t proxyPort,
                                 PRFileDesc **result)
{
    *result = PR_OpenTCPSocket(family);
    if (!*result)
        return SECFailure;

    return SOCKSIOLayerAddToSocket(family,
                                            host, 
                                            port,
                                            proxyHost,
                                            proxyPort,
                                            *result);
}

SECStatus
SOCKS5Socket_AddTo(int32_t family,
                                   const char *host,
                                   int32_t port,
                                   const char *proxyHost,
                                   int32_t proxyPort,
                                   PRFileDesc *sock)
{
    return SOCKSIOLayerAddToSocket(family,
                                            host, 
                                            port,
                                            proxyHost,
                                            proxyPort,
                                            sock);
}
