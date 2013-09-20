/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
**
** sphere-probe utility, originally based on NSS tstclnt code.
**
*/

#include "secutil.h"
#include "basicutil.h"

#if defined(XP_UNIX)
#include <unistd.h>
#else
#include <ctype.h>	/* for isalpha() */
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>

#include "nspr.h"
#include "prio.h"
#include "prnetdb.h"
#include "nss.h"
#include "ocsp.h"
#include "ssl.h"
#include "sslproto.h"
#include "pk11func.h"
#include "plgetopt.h"
#include "plstr.h"

#if defined(WIN32)
#include <fcntl.h>
#include <io.h>
#endif

#define PRINTF  if (verbose)  printf
#define FPRINTF if (verbose) fprintf

#define numDetectors 5
#define requiredDetectorMatches 4

#define MAX_WAIT_FOR_SERVER 600
#define WAIT_INTERVAL       100

#define EXIT_CODE_HANDSHAKE_FAILED 254

PRIntervalTime maxInterval    = PR_INTERVAL_NO_TIMEOUT;

int ssl2CipherSuites[] = {
    SSL_EN_RC4_128_WITH_MD5,			/* A */
    SSL_EN_RC4_128_EXPORT40_WITH_MD5,		/* B */
    SSL_EN_RC2_128_CBC_WITH_MD5,		/* C */
    SSL_EN_RC2_128_CBC_EXPORT40_WITH_MD5,	/* D */
    SSL_EN_DES_64_CBC_WITH_MD5,			/* E */
    SSL_EN_DES_192_EDE3_CBC_WITH_MD5,		/* F */
    0
};

int ssl3CipherSuites[] = {
    -1, /* SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA* a */
    -1, /* SSL_FORTEZZA_DMS_WITH_RC4_128_SHA,	 * b */
    SSL_RSA_WITH_RC4_128_MD5,			/* c */
    SSL_RSA_WITH_3DES_EDE_CBC_SHA,		/* d */
    SSL_RSA_WITH_DES_CBC_SHA,			/* e */
    SSL_RSA_EXPORT_WITH_RC4_40_MD5,		/* f */
    SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,		/* g */
    -1, /* SSL_FORTEZZA_DMS_WITH_NULL_SHA,	 * h */
    SSL_RSA_WITH_NULL_MD5,			/* i */
    SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,		/* j */
    SSL_RSA_FIPS_WITH_DES_CBC_SHA,		/* k */
    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,	/* l */
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,	        /* m */
    SSL_RSA_WITH_RC4_128_SHA,			/* n */
    TLS_DHE_DSS_WITH_RC4_128_SHA,		/* o */
    SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,		/* p */
    SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA,		/* q */
    SSL_DHE_RSA_WITH_DES_CBC_SHA,		/* r */
    SSL_DHE_DSS_WITH_DES_CBC_SHA,		/* s */
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA, 	    	/* t */
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA,       	/* u */
    TLS_RSA_WITH_AES_128_CBC_SHA,     	    	/* v */
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA, 	    	/* w */
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA,       	/* x */
    TLS_RSA_WITH_AES_256_CBC_SHA,     	    	/* y */
    SSL_RSA_WITH_NULL_SHA,			/* z */
    0
};

unsigned long __cmp_umuls;
PRBool verbose;
int multiplier = 0;
PRBool clientSpeaksFirst = PR_FALSE;

static char *progName;

#if 0
void printSecurityInfo(PRFileDesc *fd)
{
    CERTCertificate * cert;
    const SECItemArray *csa;
    SSL3Statistics * ssl3stats = SSL_GetStatistics();
    SECStatus result;
    SSLChannelInfo    channel;
    SSLCipherSuiteInfo suite;

    result = SSL_GetChannelInfo(fd, &channel, sizeof channel);
    if (result == SECSuccess && 
        channel.length == sizeof channel && 
	channel.cipherSuite) {
	result = SSL_GetCipherSuiteInfo(channel.cipherSuite, 
					&suite, sizeof suite);
	if (result == SECSuccess) {
	    FPRINTF(stderr, 
	    "detector-probe: SSL version %d.%d using %d-bit %s with %d-bit %s MAC\n",
	       channel.protocolVersion >> 8, channel.protocolVersion & 0xff,
	       suite.effectiveKeyBits, suite.symCipherName, 
	       suite.macBits, suite.macAlgorithmName);
	    FPRINTF(stderr, 
	    "detector-probe: Server Auth: %d-bit %s, Key Exchange: %d-bit %s\n"
	    "         Compression: %s\n",
	       channel.authKeyBits, suite.authAlgorithmName,
	       channel.keaKeyBits,  suite.keaTypeName,
	       channel.compressionMethodName);
    	}
    }
    cert = SSL_RevealCert(fd);
    if (cert) {
	char * ip = CERT_NameToAscii(&cert->issuer);
	char * sp = CERT_NameToAscii(&cert->subject);
        if (sp) {
	    fprintf(stderr, "subject DN: %s\n", sp);
	    PORT_Free(sp);
	}
        if (ip) {
	    fprintf(stderr, "issuer  DN: %s\n", ip);
	    PORT_Free(ip);
	}
	CERT_DestroyCertificate(cert);
	cert = NULL;
    }
    fprintf(stderr,
    	"%ld cache hits; %ld cache misses, %ld cache not reusable\n"
	"%ld stateless resumes\n",
    	ssl3stats->hsh_sid_cache_hits, ssl3stats->hsh_sid_cache_misses,
	ssl3stats->hsh_sid_cache_not_ok, ssl3stats->hsh_sid_stateless_resumes);

    csa = SSL_PeerStapledOCSPResponses(fd);
    if (csa) {
        fprintf(stderr, "Received %d Cert Status items (OCSP stapled data)\n",
                csa->len);
    }
}
#endif

int
myPrintShortCertID(FILE *out, const SECItem *der, const char *m, int level)
{
    PLArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    CERTCertificate *c;
    int rv = SEC_ERROR_NO_MEMORY;
    PRBool saveWrapeState = SECU_GetWrapEnabled();
    
    if (!arena)
	return rv;

    /* Decode certificate */
    c = PORT_ArenaZNew(arena, CERTCertificate);
    if (!c)
	goto loser;
    c->arena = arena;
    rv = SEC_ASN1DecodeItem(arena, c, 
                            SEC_ASN1_GET(CERT_CertificateTemplate), der);
    if (rv) {
        SECU_Indent(out, level); 
	SECU_PrintErrMsg(out, level, "Error", "Parsing extension");
	SECU_PrintAny(out, der, "Raw", level);
	goto loser;
    }

    /* Pretty print it out */
    SECU_EnableWrap(PR_FALSE);
    SECU_Indent(out, level); fprintf(out, "%s:\n", m);
    SECU_PrintName(out, &c->subject, "Subject", level+1); fprintf(out, "\n");
    SECU_PrintName(out, &c->issuer, " Issuer", level+1); fprintf(out, "\n");
    SECU_PrintInteger(out, &c->serialNumber, " Serial Number", level+1);
    SECU_Indent(out, level+1);  fprintf(out, "Validity:\n");
    SECU_PrintTimeChoice(out, &c->validity.notBefore, "Not Before", level+2);
    SECU_PrintTimeChoice(out, &c->validity.notAfter,  "Not After ", level+2);
    SECU_PrintAlgorithmID(out, &c->signature, "Signature Algorithm", level);
    SECU_EnableWrap(saveWrapeState);
loser:
    PORT_FreeArena(arena, PR_FALSE);
    return rv;
}

static void PrintUsageHeader(const char *progName)
{
    fprintf(stderr, 
"Usage:  %s -h host [-p port]\n"
                    "[-fsv] [-c ciphers] [-Y]\n"
                    "[-V [min-version]:[max-version]] [-T]\n"
                    "[-q [-t seconds]]\n", 
            progName);
}

static void PrintParameterUsage(void)
{
    fprintf(stderr, "%-20s Hostname to connect with\n", "-h host");
    fprintf(stderr, "%-20s Port number for SSL server\n", "-p port");
    fprintf(stderr, 
            "%-20s Restricts the set of enabled SSL/TLS protocols versions.\n"
            "%-20s SSL 3 and newer versions are enabled by default.\n"
            "%-20s Possible values for min/max: ssl2 ssl3 tls1.0 tls1.1 tls1.2\n"
            "%-20s Example: \"-V ssl3:\" enables SSL 3 and newer.\n",
            "-V [min]:[max]", "", "", "");
    fprintf(stderr, "%-20s Client speaks first. \n", "-f");
    fprintf(stderr, "%-20s Disable SSL socket locking.\n", "-s");
    fprintf(stderr, "%-20s Verbose progress reporting.\n", "-v");
    fprintf(stderr, "%-20s Ping the server and then exit.\n", "-q");
    fprintf(stderr, "%-20s Timeout for server ping (default: no timeout).\n", "-t seconds");
    fprintf(stderr, "%-20s Enable the session ticket extension.\n", "-u");
    fprintf(stderr, "%-20s Enable compression.\n", "-z");
    fprintf(stderr, "%-20s Enable false start.\n", "-g");
    fprintf(stderr, "%-20s Enable the cert_status extension (OCSP stapling).\n", "-T");
    fprintf(stderr, "%-20s Restrict ciphers\n", "-c ciphers");
    fprintf(stderr, "%-20s Print cipher values allowed for parameter -c and exit\n", "-Y");
}

static void Usage(const char *progName)
{
    PrintUsageHeader(progName);
    PrintParameterUsage();
    exit(1);
}

static void PrintCipherUsage(const char *progName)
{
    PrintUsageHeader(progName);
    fprintf(stderr, "%-20s Letter(s) chosen from the following list\n", 
                    "-c ciphers");
    fprintf(stderr, 
"A    SSL2 RC4 128 WITH MD5\n"
"B    SSL2 RC4 128 EXPORT40 WITH MD5\n"
"C    SSL2 RC2 128 CBC WITH MD5\n"
"D    SSL2 RC2 128 CBC EXPORT40 WITH MD5\n"
"E    SSL2 DES 64 CBC WITH MD5\n"
"F    SSL2 DES 192 EDE3 CBC WITH MD5\n"
"\n"
"c    SSL3 RSA WITH RC4 128 MD5\n"
"d    SSL3 RSA WITH 3DES EDE CBC SHA\n"
"e    SSL3 RSA WITH DES CBC SHA\n"
"f    SSL3 RSA EXPORT WITH RC4 40 MD5\n"
"g    SSL3 RSA EXPORT WITH RC2 CBC 40 MD5\n"
"i    SSL3 RSA WITH NULL MD5\n"
"j    SSL3 RSA FIPS WITH 3DES EDE CBC SHA\n"
"k    SSL3 RSA FIPS WITH DES CBC SHA\n"
"l    SSL3 RSA EXPORT WITH DES CBC SHA\t(new)\n"
"m    SSL3 RSA EXPORT WITH RC4 56 SHA\t(new)\n"
"n    SSL3 RSA WITH RC4 128 SHA\n"
"o    SSL3 DHE DSS WITH RC4 128 SHA\n"
"p    SSL3 DHE RSA WITH 3DES EDE CBC SHA\n"
"q    SSL3 DHE DSS WITH 3DES EDE CBC SHA\n"
"r    SSL3 DHE RSA WITH DES CBC SHA\n"
"s    SSL3 DHE DSS WITH DES CBC SHA\n"
"t    SSL3 DHE DSS WITH AES 128 CBC SHA\n"
"u    SSL3 DHE RSA WITH AES 128 CBC SHA\n"
"v    SSL3 RSA WITH AES 128 CBC SHA\n"
"w    SSL3 DHE DSS WITH AES 256 CBC SHA\n"
"x    SSL3 DHE RSA WITH AES 256 CBC SHA\n"
"y    SSL3 RSA WITH AES 256 CBC SHA\n"
"z    SSL3 RSA WITH NULL SHA\n"
"\n"
":WXYZ  Use cipher with hex code { 0xWX , 0xYZ } in TLS\n"
	);
    exit(1);
}

void
milliPause(PRUint32 milli)
{
    PRIntervalTime ticks = PR_MillisecondsToInterval(milli);
    PR_Sleep(ticks);
}

void
disableAllSSLCiphers(void)
{
    const PRUint16 *cipherSuites = SSL_GetImplementedCiphers();
    int             i            = SSL_GetNumImplementedCiphers();
    SECStatus       rv;

    /* disable all the SSL3 cipher suites */
    while (--i >= 0) {
	PRUint16 suite = cipherSuites[i];
        rv = SSL_CipherPrefSetDefault(suite, PR_FALSE);
	if (rv != SECSuccess) {
	    PRErrorCode err = PR_GetError();
	    fprintf(stderr,
	            "SSL_CipherPrefSet didn't like value 0x%04x (i = %d): %s\n",
	    	   suite, i, SECU_Strerror(err));
	    exit(2);
	}
    }
}

typedef struct
{
   void * dbHandle;    /* Certificate database handle to use while
                        * authenticating the peer's certificate. */
   PRBool requireDataForIntermediates;
   CERTCertificate *detectorCerts[numDetectors];
} ServerCertAuth;




static SECStatus 
myGetCertAuthCertificate(void *arg, PRFileDesc *fd, PRBool checkSig,
                         PRBool isServer)
{
    CERTCertificate **cert = (CERTCertificate **)arg;
    *cert = SSL_RevealCert(fd);
    if (!cert) {
	exit(254);
    }
    PORT_SetError(SEC_ERROR_CERT_VALID);
    return SECFailure;
}

static SECStatus 
ownAuthCertificate(void *arg, PRFileDesc *fd, PRBool checkSig,
                       PRBool isServer)
{
    ServerCertAuth * serverCertAuth = (ServerCertAuth *) arg;
    CERTCertificate *cert;

    cert = SSL_RevealCert(fd);
    if (!cert) {
	exit(254);
    }

    {
	int i;
	int matches = 0;
	for (i = 0; i < numDetectors; ++i) {
	    if (serverCertAuth->detectorCerts[i]
		&& SECITEM_CompareItem(&serverCertAuth->detectorCerts[i]->derCert,
				       &cert->derCert) == SECEqual) {
		++matches;
	    }
	}
	fprintf(stderr, "Server's certificate matches with %d detectors\n", matches);
	SECU_PrintSignedContent(stdout, &cert->derCert,
			    "Certificate", 0, (SECU_PPFunc)myPrintShortCertID);
	if (matches < requiredDetectorMatches) {
	    fprintf(stderr, "FAILURE\n");
	    CERT_DestroyCertificate(cert);
	    PORT_SetError(SEC_ERROR_CERT_NOT_VALID);
	    return SECFailure;
	}
    }

    fprintf(stderr, "SUCCESS\n");
    CERT_DestroyCertificate(cert);
    PORT_SetError(SEC_ERROR_CERT_VALID);
    return SECFailure;
}

static void
printHostNameAndAddr(const char * host, const PRNetAddr * addr)
{
    PRUint16 port = PR_NetAddrInetPort(addr);
    char addrBuf[80];
    PRStatus st = PR_NetAddrToString(addr, addrBuf, sizeof addrBuf);

    if (st == PR_SUCCESS) {
	port = PR_ntohs(port);
	FPRINTF(stderr, "%s: connecting to %s:%hu (address=%s)\n",
	       progName, host, port, addrBuf);
    }
}

#define SSOCK_FD 0
#define STDIN_FD 1

#define HEXCHAR_TO_INT(c, i) \
    if (((c) >= '0') && ((c) <= '9')) { \
	i = (c) - '0'; \
    } else if (((c) >= 'a') && ((c) <= 'f')) { \
	i = (c) - 'a' + 10; \
    } else if (((c) >= 'A') && ((c) <= 'F')) { \
	i = (c) - 'A' + 10; \
    } else { \
	Usage(progName); \
    }

extern SECStatus
SOCKS5Socket_New(int32_t family,
		 const char *host, 
		 int32_t port,
		 const char *proxyHost,
		 int32_t proxyPort,
		 PRFileDesc **result);

SECStatus
SOCKS5Socket_AddTo(int32_t family,
		   const char *host,
		   int32_t port,
		   const char *proxyHost,
		   int32_t proxyPort,
		   PRFileDesc *sock);

static int
queryDetectors(PRFileDesc *model, const char *host, PRUint16 portno,
		 PRUint16 *ports, PRFileDesc **sockets, CERTCertificate **detectorCerts,
		 PRIntervalTime detectorTimeout)
{
    int i;
    PRStatus status;
    PRNetAddr addr;
    PRSocketOptionData opt;
    PRPollDesc         pollset[1];
    PRInt32            filesReady;
    enum { 
	connect_socks, 
	wait_for_socks, 
	connect_destination, 
	wait_connect, 
	wait_for_handshake, 
	stage_done,
	stage_failed
    } stage[numDetectors];
    int count_success = 0;
    int count_failed = 0;
    
    if (!numDetectors || !ports || !sockets) {
	return PR_FALSE;
    }

    status = PR_StringToNetAddr("127.0.0.1", &addr);
    if (status != PR_SUCCESS) {
	SECU_PrintError(progName, "error setting proxy address");
	return PR_FALSE;
    }

    for (i = 0; i < numDetectors; ++i) {
	stage[i] = connect_socks;
	sockets[i] = NULL;
	detectorCerts[i] = NULL;
    }

    i = -1;
    while (count_failed+count_success < numDetectors) {
	PRFileDesc *s = NULL; /* shortcut reference */
	
	/* try to make progress with the next detector */
	if (++i >= numDetectors) { i = 0; }
	s = sockets[i];

	if (stage[i] == connect_socks) {
	    s = PR_OpenTCPSocket(addr.raw.family);
	    sockets[i] = s;
	    if (!s) {
	       SECU_PrintError(progName, "error creating socket");
	       stage[i] = stage_failed;
	       ++count_failed;
	    }
	    else {
		addr.inet.port = PR_htons(ports[i]);
		opt.option = PR_SockOpt_Nonblocking;
		opt.value.non_blocking = PR_TRUE;
		PR_SetSocketOption(s, &opt);
		SOCKS5Socket_AddTo(PR_AF_INET, host, portno, "127.0.0.1", ports[i], s);
		status = PR_Connect(s, &addr, PR_INTERVAL_NO_TIMEOUT);
		if (status == PR_SUCCESS) {
		    stage[i] = connect_destination;
		    FPRINTF(stderr, "%d: next connect_destination\n", i);
		} else {
		    PRErrorCode err = PR_GetError();
		    if (err == PR_IN_PROGRESS_ERROR) {
			stage[i] = wait_for_socks;
			FPRINTF(stderr, "%d: next wait_for_socks\n", i);
		    } else {
			SECU_PrintError(progName, "unable to connect");
			stage[i] = stage_failed;
			++count_failed;
		    }
		}
	    }
	}
	
	if (stage[i] == wait_for_socks) {
	    pollset[SSOCK_FD].in_flags = PR_POLL_WRITE | PR_POLL_EXCEPT;
	    pollset[SSOCK_FD].out_flags = 0;
	    pollset[SSOCK_FD].fd = s;
	    filesReady = PR_Poll(pollset, 1, PR_INTERVAL_NO_TIMEOUT);
	    if (filesReady < 0) {
		SECU_PrintError(progName, "unable to connect (poll) 1");
		stage[i] = stage_failed;
		++count_failed;
	    } else if (filesReady == 0) {	/* shouldn't happen! */
		FPRINTF(stderr, "%s: PR_Poll returned zero!\n", progName);
		stage[i] = stage_failed;
		++count_failed;
	    } else {
		status = PR_ConnectContinue(s, pollset[SSOCK_FD].out_flags);
		if (status == PR_SUCCESS) {
		    PRFileDesc *removed_layer;
		    removed_layer = PR_PopIOLayer(s, PR_TOP_IO_LAYER);
		    PR_DELETE(removed_layer);
		    stage[i] = connect_destination;
		    FPRINTF(stderr, "%d: next connect_destination\n", i);
		} else {
		    PRErrorCode err = PR_GetError();
		    if (err != PR_WOULD_BLOCK_ERROR && err != PR_IN_PROGRESS_ERROR) {
			SECU_PrintError(progName, "unable to connect (poll) 2");
			stage[i] = stage_failed;
			++count_failed;
		    }
		}
	    }
	}

	if (stage[i] == connect_destination) {
	    s = SSL_ImportFD(model, s);
	    if (!s) {
		SECU_PrintError(progName, "error importing socket");
		stage[i] = stage_failed;
		++count_failed;
	    }
	    else {
		sockets[i] = s;
		SSL_SetURL(s, host);
		detectorCerts[i] = NULL;
		SSL_AuthCertificateHook(s, myGetCertAuthCertificate, &(detectorCerts[i]));
		status = PR_Connect(s, &addr, PR_INTERVAL_NO_TIMEOUT);
		if (status == PR_SUCCESS) {
		    stage[i] = wait_for_handshake;
		    FPRINTF(stderr, "%d: next wait_for_handshake\n", i);
		    SSL_ForceHandshake(s);
		} else {
		    PRErrorCode err = PR_GetError();
		    if (err == PR_IN_PROGRESS_ERROR) {
			stage[i] = wait_connect;
			FPRINTF(stderr, "%d: next wait_connect\n", i);
		    } else {
			SECU_PrintError(progName, "unable to connect");
			stage[i] = stage_failed;
			++count_failed;
		    }
		}
	    }
	}

	if (stage[i] == wait_connect) {
	    pollset[SSOCK_FD].in_flags = PR_POLL_WRITE | PR_POLL_EXCEPT;
	    pollset[SSOCK_FD].out_flags = 0;
	    pollset[SSOCK_FD].fd = s;
	    filesReady = PR_Poll(pollset, 1, PR_INTERVAL_NO_TIMEOUT);
	    if (filesReady < 0) {
		SECU_PrintError(progName, "unable to connect (poll) 3");
		stage[i] = stage_failed;
		++count_failed;
	    } else if (filesReady == 0) {	/* shouldn't happen! */
		FPRINTF(stderr, "%s: PR_Poll returned zero!\n", progName);
		stage[i] = stage_failed;
		++count_failed;
	    } else {
		status = PR_GetConnectStatus(pollset);
		if (status == PR_SUCCESS) {
		    stage[i] = wait_for_handshake;
		    FPRINTF(stderr, "%d: next wait_for_handshake\n", i);
		    SSL_ForceHandshake(s);
		} else {
		    if (PR_GetError() != PR_IN_PROGRESS_ERROR) {
			SECU_PrintError(progName, "unable to connect (poll) 4");
			stage[i] = stage_failed;
			++count_failed;
		    }
		}
	    }
	}

	if (stage[i] == wait_for_handshake) {
	    char buf[1];

	    pollset[SSOCK_FD].fd        = s;
	    pollset[SSOCK_FD].in_flags  = PR_POLL_EXCEPT |
					  (clientSpeaksFirst ? 0 : PR_POLL_READ);
	    pollset[SSOCK_FD].out_flags = 0;
	    filesReady = PR_Poll(pollset, 1, PR_INTERVAL_NO_TIMEOUT);
	    if (filesReady < 0) {
		SECU_PrintError(progName, "select failed");
		stage[i] = stage_failed;
		++count_failed;
	    } else if (filesReady == 0) {	/* shouldn't happen! */
		FPRINTF(stderr, "%s: PR_Poll returned zero!\n", progName);
		stage[i] = stage_failed;
		++count_failed;
	    } else {
		FPRINTF(stderr, "%s: PR_Poll returned!\n", progName);
		if (   (pollset[SSOCK_FD].out_flags & PR_POLL_READ) 
		    || (pollset[SSOCK_FD].out_flags & PR_POLL_ERR)  
		    #ifdef PR_POLL_HUP
		    || (pollset[SSOCK_FD].out_flags & PR_POLL_HUP)
		    #endif
		    ) {
		    int nb = PR_Recv(pollset[SSOCK_FD].fd, buf, sizeof buf, 0, maxInterval);
		    FPRINTF(stderr, "%s: Read from server %d bytes\n", progName, nb);
		    if (nb < 0) {
			PRErrorCode err = PR_GetError();
			if (err == SEC_ERROR_CERT_VALID) {
			    stage[i] = stage_done;
			    ++count_success;
			    FPRINTF(stderr, "%d: done\n", i);
			} else if (err != PR_WOULD_BLOCK_ERROR) {
			    SECU_PrintError(progName, "read from socket failed");
			    stage[i] = stage_failed;
			    ++count_failed;
			}
		    } else if (nb == 0) {
			/* EOF from socket... stop polling socket for read */
			pollset[SSOCK_FD].in_flags = 0;
			/* no data available, but the handshake has completed */
			stage[i] = stage_done;
			++count_success;
			FPRINTF(stderr, "%d: done\n", i);
		    } else {
			/* we received content bytes, the handshake has completed */
			stage[i] = stage_done;
			++count_success;
			FPRINTF(stderr, "%d: done\n", i);
		    }
		}
	    }
	}
    }
    for (i = 0; i < numDetectors; i++) {
	if (sockets[i]) {
	    PR_Close(sockets[i]);
	}
    }

    FPRINTF(stderr, "queryDetectors done, %d success, %d failed\n", count_success, count_failed);
    return count_success;
}

int main(int argc, char **argv)
{
    PRFileDesc *       s;
    char *             host	=  NULL;
    char *             cipherString = NULL;
    char *             tmp;
    SECStatus          rv;
    PRStatus           status;
    PRInt32            filesReady;
    SSLVersionRange    enabledVersions;
    PRBool             enableSSL2 = PR_FALSE;
    int                disableLocking = 0;
    int                enableSessionTickets = 0;
    int                enableCompression = 0;
    int                enableFalseStart = 0;
    int                enableCertStatus = 0;
    PRSocketOptionData opt;
    PRNetAddr          addr;
    PRPollDesc         pollset[2];
    PRBool             pingServerFirst = PR_FALSE;
    int                pingTimeoutSeconds = -1;
    ServerCertAuth     serverCertAuth;
    int                error = 0;
    PRUint16           portno = 443;
    PLOptState *optstate;
    PLOptStatus optstatus;
    PRStatus prStatus;
    PRUint16 detectorPorts[numDetectors];
    PRFileDesc *detectorSockets[numDetectors];
    PRIntervalTime detectorTimeout = PR_MillisecondsToInterval(20000);
    int numDetectorResults;

    serverCertAuth.dbHandle = NULL;
    serverCertAuth.requireDataForIntermediates = PR_FALSE;

    progName = strrchr(argv[0], '/');
    if (!progName)
	progName = strrchr(argv[0], '\\');
    progName = progName ? progName+1 : argv[0];

    tmp = PR_GetEnv("NSS_DEBUG_TIMEOUT");
    if (tmp && tmp[0]) {
       int sec = PORT_Atoi(tmp);
       if (sec > 0) {
           maxInterval = PR_SecondsToInterval(sec);
       }
    }

    SSL_VersionRangeGetSupported(ssl_variant_stream, &enabledVersions);

    optstate = PL_CreateOptState(argc, argv,
                                 "TV:Yc:fgh:m:p:qst:uvz");
    while ((optstatus = PL_GetNextOpt(optstate)) == PL_OPT_OK) {
	switch (optstate->option) {
	  case '?':
	  default : Usage(progName); 			break;

	  case 'I': /* reserved for OCSP multi-stapling */ break;

          case 'T': enableCertStatus = 1;               break;

          case 'V': if (SECU_ParseSSLVersionRangeString(optstate->value,
                            enabledVersions, enableSSL2,
                            &enabledVersions, &enableSSL2) != SECSuccess) {
                        Usage(progName);
                    }
                    break;

          case 'Y': PrintCipherUsage(progName); exit(0); break;

          case 'c': cipherString = PORT_Strdup(optstate->value); break;

          case 'g': enableFalseStart = 1; 		break;

          case 'f': clientSpeaksFirst = PR_TRUE;        break;

          case 'h': host = PORT_Strdup(optstate->value);	break;

	  case 'm':
	    multiplier = atoi(optstate->value);
	    if (multiplier < 0)
	    	multiplier = 0;
	    break;

	  case 'p': portno = (PRUint16)atoi(optstate->value);	break;

	  case 'q': pingServerFirst = PR_TRUE;          break;

	  case 's': disableLocking = 1;                 break;
          
          case 't': pingTimeoutSeconds = atoi(optstate->value); break;

	  case 'u': enableSessionTickets = PR_TRUE;	break;

	  case 'v': verbose++;	 			break;

	  case 'z': enableCompression = 1;		break;
	}
    }

    PL_DestroyOptState(optstate);

    if (optstatus == PL_OPT_BAD)
	Usage(progName);

    if (!host || !portno) 
    	Usage(progName);

    PR_Init( PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

    PK11_SetPasswordFunc(SECU_GetModulePassword);

    status = PR_StringToNetAddr(host, &addr);
    if (status == PR_SUCCESS) {
	addr.inet.port = PR_htons(portno);
    } else {
	/* Lookup host */
	PRAddrInfo *addrInfo;
	void       *enumPtr   = NULL;

	addrInfo = PR_GetAddrInfoByName(host, PR_AF_UNSPEC, 
					PR_AI_ADDRCONFIG | PR_AI_NOCANONNAME);
	if (!addrInfo) {
	    SECU_PrintError(progName, "error looking up host");
	    return 1;
	}
	do {
	    enumPtr = PR_EnumerateAddrInfo(enumPtr, addrInfo, portno, &addr);
	} while (enumPtr != NULL &&
		 addr.raw.family != PR_AF_INET &&
		 addr.raw.family != PR_AF_INET6);
	PR_FreeAddrInfo(addrInfo);
	if (enumPtr == NULL) {
	    SECU_PrintError(progName, "error looking up host address");
	    return 1;
	}
    }

    printHostNameAndAddr(host, &addr);

    if (pingServerFirst) {
	int iter = 0;
	PRErrorCode err;
        int max_attempts = MAX_WAIT_FOR_SERVER;
        if (pingTimeoutSeconds >= 0) {
          /* If caller requested a timeout, let's try just twice. */
          max_attempts = 2;
        }
	do {
            PRIntervalTime timeoutInterval = PR_INTERVAL_NO_TIMEOUT;
	    s = PR_OpenTCPSocket(addr.raw.family);
	    if (s == NULL) {
		SECU_PrintError(progName, "Failed to create a TCP socket");
	    }
	    opt.option             = PR_SockOpt_Nonblocking;
	    opt.value.non_blocking = PR_FALSE;
	    prStatus = PR_SetSocketOption(s, &opt);
	    if (prStatus != PR_SUCCESS) {
		PR_Close(s);
		SECU_PrintError(progName, 
		                "Failed to set blocking socket option");
		return 1;
	    }
            if (pingTimeoutSeconds >= 0) {
              timeoutInterval = PR_SecondsToInterval(pingTimeoutSeconds);
            }
	    prStatus = PR_Connect(s, &addr, timeoutInterval);
	    if (prStatus == PR_SUCCESS) {
    		PR_Shutdown(s, PR_SHUTDOWN_BOTH);
    		PR_Close(s);
    		PR_Cleanup();
		return 0;
	    }
	    err = PR_GetError();
	    if ((err != PR_CONNECT_REFUSED_ERROR) && 
	        (err != PR_CONNECT_RESET_ERROR)) {
		SECU_PrintError(progName, "TCP Connection failed");
		return 1;
	    }
	    PR_Close(s);
	    PR_Sleep(PR_MillisecondsToInterval(WAIT_INTERVAL));
	} while (++iter < max_attempts);
	SECU_PrintError(progName, 
                     "Client timed out while waiting for connection to server");
	return 1;
    }

    rv = NSS_NoDB_Init(NULL);
    if (rv != SECSuccess) {
        SECU_PrintError(progName, "unable to init NSS");
        return 1;
    }

    /* set the policy bits true for all the cipher suites. */
    NSS_SetDomesticPolicy();

    /* all the SSL2 and SSL3 cipher suites are enabled by default. */
    if (cipherString) {
        /* disable all the ciphers, then enable the ones we want. */
        disableAllSSLCiphers();
    }

    /* Create socket */
    s = PR_OpenTCPSocket(addr.raw.family);
    if (s == NULL) {
       SECU_PrintError(progName, "error creating socket");
       return 1;
    }

    opt.option = PR_SockOpt_Nonblocking;
    opt.value.non_blocking = PR_TRUE;
    PR_SetSocketOption(s, &opt);
    /*PR_SetSocketOption(PR_GetSpecialFD(PR_StandardInput), &opt);*/

    s = SSL_ImportFD(NULL, s);
    if (s == NULL) {
	SECU_PrintError(progName, "error importing socket");
	return 1;
    }

    rv = SSL_OptionSet(s, SSL_SECURITY, 1);
    if (rv != SECSuccess) {
        SECU_PrintError(progName, "error enabling socket");
	return 1;
    }

    rv = SSL_OptionSet(s, SSL_HANDSHAKE_AS_CLIENT, 1);
    if (rv != SECSuccess) {
	SECU_PrintError(progName, "error enabling client handshake");
	return 1;
    }

    /* all the SSL2 and SSL3 cipher suites are enabled by default. */
    if (cipherString) {
    	char *cstringSaved = cipherString;
    	int ndx;

	while (0 != (ndx = *cipherString++)) {
	    int  cipher;

	    if (ndx == ':') {
		int ctmp;

		cipher = 0;
		HEXCHAR_TO_INT(*cipherString, ctmp)
		cipher |= (ctmp << 12);
		cipherString++;
		HEXCHAR_TO_INT(*cipherString, ctmp)
		cipher |= (ctmp << 8);
		cipherString++;
		HEXCHAR_TO_INT(*cipherString, ctmp)
		cipher |= (ctmp << 4);
		cipherString++;
		HEXCHAR_TO_INT(*cipherString, ctmp)
		cipher |= ctmp;
		cipherString++;
	    } else {
		const int *cptr;

		if (! isalpha(ndx))
		    Usage(progName);
		cptr = islower(ndx) ? ssl3CipherSuites : ssl2CipherSuites;
		for (ndx &= 0x1f; (cipher = *cptr++) != 0 && --ndx > 0; ) 
		    /* do nothing */;
	    }
	    if (cipher > 0) {
		SECStatus status;
		status = SSL_CipherPrefSet(s, cipher, SSL_ALLOWED);
		if (status != SECSuccess) 
		    SECU_PrintError(progName, "SSL_CipherPrefSet()");
	    } else {
		Usage(progName);
	    }
	}
	PORT_Free(cstringSaved);
    }

    rv = SSL_VersionRangeSet(s, &enabledVersions);
    if (rv != SECSuccess) {
        SECU_PrintError(progName, "error setting SSL/TLS version range ");
        return 1;
    }

    rv = SSL_OptionSet(s, SSL_ENABLE_SSL2, enableSSL2);
    if (rv != SECSuccess) {
       SECU_PrintError(progName, "error enabling SSLv2 ");
       return 1;
    }

    rv = SSL_OptionSet(s, SSL_V2_COMPATIBLE_HELLO, enableSSL2);
    if (rv != SECSuccess) {
        SECU_PrintError(progName, "error enabling SSLv2 compatible hellos ");
        return 1;
    }

    /* disable SSL socket locking */
    rv = SSL_OptionSet(s, SSL_NO_LOCKS, disableLocking);
    if (rv != SECSuccess) {
	SECU_PrintError(progName, "error disabling SSL socket locking");
	return 1;
    }

    /* enable Session Ticket extension. */
    rv = SSL_OptionSet(s, SSL_ENABLE_SESSION_TICKETS, enableSessionTickets);
    if (rv != SECSuccess) {
	SECU_PrintError(progName, "error enabling Session Ticket extension");
	return 1;
    }

    /* enable compression. */
    rv = SSL_OptionSet(s, SSL_ENABLE_DEFLATE, enableCompression);
    if (rv != SECSuccess) {
	SECU_PrintError(progName, "error enabling compression");
	return 1;
    }

    /* enable false start. */
    rv = SSL_OptionSet(s, SSL_ENABLE_FALSE_START, enableFalseStart);
    if (rv != SECSuccess) {
	SECU_PrintError(progName, "error enabling false start");
	return 1;
    }

    /* enable cert status (OCSP stapling). */
    rv = SSL_OptionSet(s, SSL_ENABLE_OCSP_STAPLING, enableCertStatus);
    if (rv != SECSuccess) {
        SECU_PrintError(progName, "error enabling cert status (OCSP stapling)");
        return 1;
    }

    serverCertAuth.dbHandle = CERT_GetDefaultCertDB();

#if 0
    CERTCertificate *peerCert = NULL;
    SSL_AuthCertificateHook(fd, myGetCertAuthCertificate, &peerCert);
    if (peerCert)
	CERT_DestroyCertificate(peerCert);
    SSL_RevealCert
#endif

    detectorPorts[0] = 9160;
    detectorPorts[1] = 9162;
    detectorPorts[2] = 9164;
    detectorPorts[3] = 9166;
    detectorPorts[4] = 9168;

    /* use s as a model socket for the detector connections */
    numDetectorResults = 
	queryDetectors(s, host, portno, 
		       detectorPorts, detectorSockets, 
		       serverCertAuth.detectorCerts, detectorTimeout);

    if (verbose)
    {
	int test = 0;
	int i;
	for (i = 0; i < numDetectors; ++i) {
	    if (serverCertAuth.detectorCerts[i]) {
		SECU_PrintSignedContent(stdout, &serverCertAuth.detectorCerts[i]->derCert,
				    "Certificate", 0, (SECU_PPFunc)myPrintShortCertID);
		++test;
	    }
	}
	FPRINTF(stderr, "we obtained %d detector certificates\n", test);
    }

    SSL_AuthCertificateHook(s, ownAuthCertificate, &serverCertAuth);
    SSL_SetURL(s, host);

    /* Try to connect to the server */
    status = PR_Connect(s, &addr, PR_INTERVAL_NO_TIMEOUT);
    if (status != PR_SUCCESS) {
	if (PR_GetError() == PR_IN_PROGRESS_ERROR) {
	    if (verbose)
		SECU_PrintError(progName, "connect");
	    milliPause(50 * multiplier);
	    pollset[SSOCK_FD].in_flags = PR_POLL_WRITE | PR_POLL_EXCEPT;
	    pollset[SSOCK_FD].out_flags = 0;
	    pollset[SSOCK_FD].fd = s;
	    while(1) {
		FPRINTF(stderr, 
		        "%s: about to call PR_Poll for connect completion!\n", 
			progName);
		filesReady = PR_Poll(pollset, 1, PR_INTERVAL_NO_TIMEOUT);
		if (filesReady < 0) {
		    SECU_PrintError(progName, "unable to connect (poll)");
		    return 1;
		}
		FPRINTF(stderr,
		        "%s: PR_Poll returned 0x%02x for socket out_flags.\n",
			progName, pollset[SSOCK_FD].out_flags);
		if (filesReady == 0) {	/* shouldn't happen! */
		    FPRINTF(stderr, "%s: PR_Poll returned zero!\n", progName);
		    return 1;
		}
		status = PR_GetConnectStatus(pollset);
		if (status == PR_SUCCESS) {
		    break;
		}
		if (PR_GetError() != PR_IN_PROGRESS_ERROR) {
		    SECU_PrintError(progName, "unable to connect (poll)");
		    return 1;
		}
		SECU_PrintError(progName, "poll");
		milliPause(50 * multiplier);
	    }
	} else {
	    SECU_PrintError(progName, "unable to connect");
	    return 1;
	}
    }

    pollset[SSOCK_FD].fd        = s;
    pollset[SSOCK_FD].in_flags  = PR_POLL_EXCEPT |
                                  (clientSpeaksFirst ? 0 : PR_POLL_READ);

    while (pollset[SSOCK_FD].in_flags) {
	char buf[1];	/* buffer for stdin */
	int nb;		/* num bytes read from stdin. */

	pollset[SSOCK_FD].out_flags = 0;

	filesReady = PR_Poll(pollset, 1, PR_INTERVAL_NO_TIMEOUT);
	if (filesReady < 0) {
	    SECU_PrintError(progName, "select failed");
	    error = 1;
	    goto done;
	}
	if (filesReady == 0) {	/* shouldn't happen! */
	    FPRINTF(stderr, "%s: PR_Poll returned zero!\n", progName);
	    return 1;
	}
	if (   (pollset[SSOCK_FD].out_flags & PR_POLL_READ) 
	    || (pollset[SSOCK_FD].out_flags & PR_POLL_ERR)  
#ifdef PR_POLL_HUP
	    || (pollset[SSOCK_FD].out_flags & PR_POLL_HUP)
#endif
	    ) {
	    nb = PR_Recv(pollset[SSOCK_FD].fd, buf, sizeof buf, 0, maxInterval);
	    if (nb < 0) {
		PRErrorCode err = PR_GetError();
		if (err == SEC_ERROR_CERT_VALID) {
		    goto done;
		} else if (err == SEC_ERROR_CERT_NOT_VALID) {
		    goto done;
		} else if (err != PR_WOULD_BLOCK_ERROR) {
		    SECU_PrintError(progName, "read from socket failed");
		    error = 1;
		    goto done;
		}
	    } else if (nb == 0) {
		/* EOF from socket... stop polling socket for read */
		pollset[SSOCK_FD].in_flags = 0;
		goto done;
	    } else {
		goto done;
	    }
	}
	milliPause(50 * multiplier);
    }

  done:
    PORT_Free(host);

    PR_Close(s);
    SSL_ClearSessionCache();
    if (NSS_Shutdown() != SECSuccess) {
        exit(1);
    }

    FPRINTF(stderr, "detector-probe: exiting with return code %d\n", error);
    PR_Cleanup();
    return error;
}
