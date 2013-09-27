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
#include "iniparser.h"

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


/*
 * -C config.ini
 *    multiple hostnames to probe repeatedly
 *    A minimal valid file looks like:
 *        [any-section-name]
 *        host = www.example.com
 *        port = 443
 *        certs = 1
 *        cert1 = expected-cert-for-host.example.com-der.or.pem)
 *    file may contain one or multiple sections
 *    each section indicates one service to probe.
 *    Each service will be probed at a random interval, between 1 minutes and 20 minutes
 *    each section starts withs a section name. Any name is OK, but must be unique in the file.
 *      [any-section-name]
 *    each section contains mandatory entries
 *      host = the hostname to connect to
 *      port = the port number of the SSL/TLS service to probe
 *      certs = number-of-comparison-certs
 *    number-of-comparison-certs must be 1 or larger
 *    There must be one or multiple entries that list the filenames
 *    that contain valid comparison certs (that will not be alerted if found)
 *    Each filename must be in binary DER format, raw binary comparison will be used.
 *      cert1 = first comparison cert filename
 *      cert2 = ...
 *      ...
 *    Each time a mismatch is found (a certificate received from a server doesn't
 *    match any of the comparison certs), then a report will be created and logged to disk.
 *    If an alert-script.sh has been configured, it will be executed and the report
 *    will be passed to the alert script as the first parameter.
 *     
 * -A alert-script.sh
 *    run with: system("alert-script.sh temp-file")
 *    temp-file is a text report of the mismatch, containing full certificates
 *    temp-file will be created by probe tool, and deleted after alert-script is done
 *    This script will also be called, if at least one local Tor spheres cannot be reached,
 *    and the report will contain TOR-SPHERE-OFFLINE
 * 
 * -R
 *    Remote Tor spheres, only.
 *    No direct connection using the local network will be performed.
 *    This could be used to hide which servers are being probed from a nearby
 *    adversary.
 * 
 * -W
 *    Using the -W you can SUPPRESS (disable) the daily success report.
 *    If this parameter hasn't been given, the behaviour is as follows:
 *    Usually, if no mismatches have been detected, the alert-script will be called
 *    once a day for testing purposes. The first line of such a test report will contain
 *    only one line with: ALL-IS-WELL
 *    This can be used to monitor that the alert-script works correctly.
 *    After startup of the program, all hosts will be tested, and if no problems were 
 *    found, the first ALL-RIGHT report will be generated immediately.
 *    The next report will be generated approximately after 24 hours.
 */

typedef struct config_entry_str {
    const char *host;
    PRUint16 portno;
    CERTCertList *allowed_certs;
    struct config_entry_str *next;
} config_entry;

PLArenaPool *config_arena = NULL;
config_entry *root_config_entry;

CERTCertificate *
LoadCertFromFile(const char *filename, PRBool ascii)
{
    CERTCertificate *cert;
    SECStatus rv;
    SECItem item = {0, NULL, 0};
    PRFileDesc* fd = PR_Open(filename, PR_RDONLY, 0777); 
    if (!fd) {
        return NULL;
    }
    rv = SECU_ReadDERFromFile(&item, fd, ascii, PR_FALSE);
    PR_Close(fd);
    if (rv != SECSuccess || !item.len) {
        PORT_Free(item.data);
        return NULL;
    }
    cert = CERT_NewTempCertificate(CERT_GetDefaultCertDB(), &item, 
				   NULL     /* nickname */, 
				   PR_FALSE /* isPerm */, 
				   PR_TRUE  /* copyDER */);
    PORT_Free(item.data);
    return cert;
}

CERTCertificate *
AppendNewCertEntry(CERTCertList *list, const char *filename)
{
    /*try ascii*/
    CERTCertificate *c = LoadCertFromFile(filename, PR_TRUE);
    if (!c) {
	/*try binary*/
	c = LoadCertFromFile(filename, PR_FALSE);
	if (!c)
	    return NULL;
    }
    CERT_AddCertToListTail(list, c);
    return c;
}

config_entry *
AppendNewConfigEntry(config_entry *root, const char *host, PRUint16 portno)
{
    config_entry *last;
    
    config_entry *ce = PORT_ArenaZNew(config_arena, config_entry);
    ce->host = PORT_ArenaStrdup(config_arena, host);
    ce->portno = portno;
    ce->allowed_certs = CERT_NewCertList();

    last = root;
    while (last && last->next) {
	last = last->next;
    }
    if (last) {
	last->next = ce;
    }
    return ce;
}

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
char *cipherString = NULL;
SSLVersionRange    enabledVersions;
PRBool             enableSSL2 = PR_FALSE;
int                disableLocking = 0;
int                enableSessionTickets = 0;
int                enableCompression = 0;
int                enableFalseStart = 0;
int                enableCertStatus = 0;
PRBool oneShotMode = PR_FALSE;
PRBool configMode = PR_FALSE;
PRUint16 detectorPorts[numDetectors];
PRFileDesc *detectorSockets[numDetectors];
PRIntervalTime detectorTimeout;

const char *config_filename = NULL;
const char *dump_filename = NULL;
const char *alert_script_filename = NULL;
PRBool allow_direct_probe = PR_TRUE;
PRBool suppress_all_is_well = PR_FALSE;

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
    SECU_PrintInteger(out, &c->serialNumber, " Serial", level+1);
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
"Usage:  %s -h host [-p port] [-C config] [-R] [-A script] [-W]\n"
                    "[-fsv] [-c ciphers] [-Y]\n"
                    "[-V [min-version]:[max-version]] [-T]\n"
            , progName);
}

static void PrintParameterUsage(void)
{
    fprintf(stderr, "One-shot mode (probe one host, then exit):\n");
    fprintf(stderr, "%-20s Hostname to connect with\n", "-h host");
    fprintf(stderr, "%-20s Port number for SSL server\n", "-p port");
    fprintf(stderr, "%-20s Dump retrieved certificates to file\n", "-D dump-file");
    fprintf(stderr, "Monitoring mode (repeatedly test, wait, test...):\n");
    fprintf(stderr, "%-20s Config file for probing hosts\n", "-C config");
    fprintf(stderr, "%-20s Remote probing, only (no direct connection)\n", "-R");
    fprintf(stderr, "%-20s Alert script that will be called on failures\n", "-A script");
    fprintf(stderr, "%-20s Suppress the daily ALL-IS-WELL report\n", "-W");
    fprintf(stderr, "Common options:\n");
    fprintf(stderr, 
            "%-20s Restricts the set of enabled SSL/TLS protocols versions.\n"
            "%-20s SSL 3 and newer versions are enabled by default.\n"
            "%-20s Possible values for min/max: ssl2 ssl3 tls1.0 tls1.1 tls1.2\n"
            "%-20s Example: \"-V ssl3:\" enables SSL 3 and newer.\n",
            "-V [min]:[max]", "", "", "");
    fprintf(stderr, "%-20s Client speaks first. \n", "-f");
    fprintf(stderr, "%-20s Disable SSL socket locking.\n", "-s");
    fprintf(stderr, "%-20s Verbose progress reporting.\n", "-v");
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

static void UsageIni(const char *progName)
{
    PrintUsageHeader(progName);
    fprintf(stderr, "error in config file\n");
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
   CERTCertificate *detectorCerts[numDetectors];
   CERTCertificate *directCert;
} ServerCertAuth;

ServerCertAuth     serverCertAuth;


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
    serverCertAuth->directCert = CERT_DupCertificate(cert);

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
#if 0
	SECU_PrintSignedContent(stdout, &cert->derCert,
			    "Certificate", 0, (SECU_PPFunc)myPrintShortCertID);
#endif
	fprintf(stdout, "The direct connection server certificate matches with %d detectors\n", matches);
	if (matches < requiredDetectorMatches) {
	    fprintf(stdout, "FAILURE\n");
	    PORT_SetError(SEC_ERROR_CERT_NOT_VALID);
	    return SECFailure;
	}
    }

    fprintf(stdout, "SUCCESS\n");
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
	FPRINTF(stdout, "%s: connecting to %s:%hu (address=%s)\n",
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

/* TODO: implement timeout */
/* TODO: retry on EOF  */
/* TODO: implement TOR-SPHERE-OFFLINE with separate error code */
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

int
probeOne(const char *host, PRUint16 portno)
{
    PRStatus           status;
    PRNetAddr          addr;
    PRFileDesc *       s;
    PRSocketOptionData opt;
    SECStatus          rv;
    int numDetectorResults;
    PRPollDesc         pollset[2];
    PRInt32            filesReady;
    int                error = 0;
    int i;

    for (i = 0; i < numDetectors; ++i) {
	serverCertAuth.detectorCerts[i] = NULL;
    }
    serverCertAuth.directCert = NULL;

    if (allow_direct_probe || oneShotMode) {
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
    } else {
	status = PR_StringToNetAddr("127.0.0.1", &addr);
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

    if (allow_direct_probe || oneShotMode) {
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
    }

done:
    PR_Close(s);
    return error;
}

void
dumpCertPEM(FILE *out, CERTCertificate *c)
{
    char * asciiDER = BTOA_DataToAscii(c->derCert.data, c->derCert.len);
    if (asciiDER) {
	fprintf(out, "%s\n%s\n%s\n", 
	        NS_CERT_HEADER, asciiDER, NS_CERT_TRAILER);
	PORT_Free(asciiDER);
    }
}

void
writeReport(FILE *out, const char *firstLine, PRBool dumpCerts)
{
    int i;
    if (firstLine) {
	fputs(firstLine, out);
	fputs("\n", out);
    }
    if (dumpCerts) {
	for (i = 0; i < numDetectors; ++i) {
	    if (serverCertAuth.detectorCerts[i]) {
		fprintf(out, "Certificate found using sphere %d:\n", i+1);
		SECU_PrintSignedContent(out, &serverCertAuth.detectorCerts[i]->derCert,
				    0, 1, (SECU_PPFunc)myPrintShortCertID);
		dumpCertPEM(out, serverCertAuth.detectorCerts[i]);
		fputs("\n", out);
	    }
	}
	if (serverCertAuth.directCert) {
	    fprintf(out, "Certificate found using direct connection:\n");
	    SECU_PrintSignedContent(out, &serverCertAuth.directCert->derCert,
				0, 1, (SECU_PPFunc)myPrintShortCertID);
	    dumpCertPEM(out, serverCertAuth.directCert);
	    fputs("\n", out);
	}
    }
}

typedef struct tempfile_str {
    char buf[32];
    FILE *fp;
} tempfile;

PRBool
getTempFile(tempfile *tf)
{
    int fd;
    strcpy(tf->buf, "temp-report-XXXXXX");
    fd = mkstemp(tf->buf);
    if (fd == -1) {
	return PR_FALSE;
    }
    tf->fp = fdopen(fd, "wb");
    if (!tf->fp) {
	close(fd);
	return PR_FALSE;
    }
    return PR_TRUE;
}

void
send_alert(const char *report_filename)
{
    char *cmd = PR_smprintf("%s %s", alert_script_filename, report_filename);
    if (!cmd)
	exit(1);
    
    system(cmd);
    PR_smprintf_free(cmd);
}

int main(int argc, char **argv)
{
    char *             host	=  NULL;
    char *             tmp;
    SECStatus          rv;
    PRUint16           portno = 443;
    PLOptState *optstate;
    PLOptStatus optstatus;
    int error = 0;

    serverCertAuth.dbHandle = NULL;
    detectorTimeout = PR_MillisecondsToInterval(20000);

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
                                 "A:C:D:RTV:WYc:fgh:m:p:suvz");
    while ((optstatus = PL_GetNextOpt(optstate)) == PL_OPT_OK) {
	switch (optstate->option) {
	  case '?':
	  default : Usage(progName); 			break;
	  case 'A': alert_script_filename = PORT_Strdup(optstate->value);
	             configMode = PR_TRUE;
		     break;
	  case 'C': config_filename = PORT_Strdup(optstate->value);
	             configMode = PR_TRUE;
		     break;
	  case 'D': dump_filename = PORT_Strdup(optstate->value);
		     oneShotMode = PR_TRUE;
		     break;
          case 'R': allow_direct_probe = PR_FALSE;
	             configMode = PR_TRUE;
		     break;
          case 'G': suppress_all_is_well = PR_TRUE;
	             configMode = PR_TRUE;
		     break;

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

          case 'h': host = PORT_Strdup(optstate->value);
		     oneShotMode = PR_TRUE;
		     break;

	  case 'm':
	    multiplier = atoi(optstate->value);
	    if (multiplier < 0)
	    	multiplier = 0;
	    break;

	  case 'p': portno = (PRUint16)atoi(optstate->value);
		     oneShotMode = PR_TRUE;
		     break;

	  case 's': disableLocking = 1;                 break;
	  case 'u': enableSessionTickets = PR_TRUE;	break;
	  case 'v': verbose++;	 			break;
	  case 'z': enableCompression = 1;		break;
	}
    }

    PL_DestroyOptState(optstate);

    if (optstatus == PL_OPT_BAD)
	Usage(progName);

    if (oneShotMode && (!host || !portno))
    	Usage(progName);
    
    if (configMode && oneShotMode)
	Usage(progName);

    if (!configMode && !oneShotMode)
	Usage(progName);
    
    if (configMode && !config_filename)
	Usage(progName);

    PR_Init( PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

    /*PK11_SetPasswordFunc(SECU_GetModulePassword);*/

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

    serverCertAuth.dbHandle = CERT_GetDefaultCertDB();

    detectorPorts[0] = 9160;
    detectorPorts[1] = 9162;
    detectorPorts[2] = 9164;
    detectorPorts[3] = 9166;
    detectorPorts[4] = 9168;

    if (configMode) {
	dictionary *d;
	const char *section, *host, *certfile;
	int portno;
	int num_sections, num_certs;
	int is, ic;
	char inikey[512];

	d = iniparser_load(config_filename);
	if (!d)
	    UsageIni(progName);

	config_arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);

	num_sections = iniparser_getnsec(d);
	for (is = 0; is < num_sections; is++) {
	    int offset = 0;
	    char *digit_pos;
	    config_entry *ce;
	    
	    section = iniparser_getsecname(d, is);
	    offset = strlen(section);
	    if (offset > sizeof(inikey)-20)
		UsageIni(progName);
	    strcpy(inikey, section);
	    strcpy(inikey+offset, ":host");
	    host = iniparser_getstring(d, inikey, NULL);
	    strcpy(inikey+offset, ":port");
	    portno = iniparser_getint(d, inikey, 0);
	    strcpy(inikey+offset, ":certs");
	    num_certs = iniparser_getint(d, inikey, 0);
	    /*following trivial code assumes one digit number of certs*/
	    if (!host || !portno || num_certs <=0 || num_certs >= 10)
		UsageIni(progName);
	    ce = AppendNewConfigEntry(root_config_entry, host, portno);
	    if (!root_config_entry)
		root_config_entry = ce;
	    strcpy(inikey+offset, ":cert");
	    digit_pos = inikey+offset + strlen(inikey+offset);
	    *digit_pos = '0';
	    *(digit_pos+1) = 0;
	    for (ic = 1; ic <= num_certs; ic++) {
		++(*digit_pos);
		certfile = iniparser_getstring(d, inikey, NULL);
		AppendNewCertEntry(ce->allowed_certs, certfile);
	    }
	}
    }

    if (oneShotMode) {
	int i;
	error = probeOne(host, portno);
	if (dump_filename) {
	    FILE *fp = fopen(dump_filename, "w");
	    if (fp) {
		writeReport(fp, 0, PR_TRUE);
		fclose(fp);
	    }
	}
	for (i = 0; i < numDetectors; ++i) {
	    if (serverCertAuth.detectorCerts[i]) {
		CERT_DestroyCertificate(serverCertAuth.detectorCerts[i]);
	    }
	}
	if (serverCertAuth.directCert) {
	    CERT_DestroyCertificate(serverCertAuth.directCert);
	}
    } else if (configMode) {
	int i;
	PRTime last_all_is_well_report = 0;
	PRBool foundBadCertInCycle = PR_FALSE;
	PRBool serverMismatched = PR_FALSE;
	config_entry *entry = root_config_entry;
	while (entry) {
	    printf("probing %s:%d\n", entry->host, entry->portno);
	    serverMismatched = PR_FALSE;
	    error = probeOne(entry->host, entry->portno);

	    /* iterate (numDetectors+1) times */
	    for (i = 0; i <= numDetectors; ++i) {
		CERTCertificate *network_cert = NULL;
		if (i < numDetectors) {
		    network_cert = serverCertAuth.detectorCerts[i];
		} else {
		    if (allow_direct_probe) {
			network_cert = serverCertAuth.directCert;
		    }
		}
		if (network_cert) {
		    CERTCertListNode *node = CERT_LIST_HEAD(entry->allowed_certs);
		    while ( ! CERT_LIST_END(node, entry->allowed_certs) ) {
			if (SECITEM_CompareItem(&network_cert->derCert,
					        &node->cert->derCert) != SECEqual) {
			    serverMismatched = PR_TRUE;
			    printf("found mismatching cert in ");
			    if (i < numDetectors)
				printf("sphere %d\n", i+1);
			    else
				printf("direct connection\n");
			}
			node = CERT_LIST_NEXT(node);
		    }
		}
	    }
	    if (!serverMismatched) {
		printf("probes matched our expectations\n");
	    }
	    if (serverMismatched) {
		char *header;
		tempfile tf;

		foundBadCertInCycle = PR_TRUE;
		if (getTempFile(&tf)) {
		    /* TODO, better handling for NULL, failure to alert is bad... */
		    header = PR_smprintf("ALERT - unexpected certificates at %s:%d",
					 entry->host, entry->portno);
		    writeReport(tf.fp, header, PR_TRUE);
		    PR_smprintf_free(header);
		    fclose(tf.fp);
		    send_alert(tf.buf);
		    unlink(tf.buf);
		}
	    }

	    entry = entry->next;
	    if (!entry) {
		/* we've completed a cycle */
		if (!foundBadCertInCycle && !suppress_all_is_well) {
		    /* is it time for the daily all-is-well report? */
		    const PRUint64 microseconds_per_day = 
			1000000ULL * 60 * 60 * 24;
		    PRTime now = PR_Now();
		    if (now < last_all_is_well_report /* epoch rollover */
		        || now > (last_all_is_well_report+microseconds_per_day)) {
			tempfile tf;
			if (getTempFile(&tf)) {
			    writeReport(tf.fp, "ALL-IS-WELL", PR_FALSE);
			    fclose(tf.fp);
			    send_alert(tf.buf);
			    unlink(tf.buf);
			    last_all_is_well_report = now;
			}
		    }
		}

		foundBadCertInCycle = PR_FALSE;
		entry = root_config_entry;
		{
		    unsigned char r;
		    int sleeptime = 0;
		    /* let's sleep for a random period between 1 and 18 minutes,
		     * max(one random byte) * 4 = 1020 seconds = 17 minutes */
		    PK11_GenerateRandom(&r, 1);
		    sleeptime = 60 + r*4;
		    printf("sleeping %d:%02d minutes...\n", sleeptime/60, sleeptime%60);
		    PR_Sleep(PR_SecondsToInterval(sleeptime));
		}
	    }
	}
    }

    SSL_ClearSessionCache();
    if (NSS_Shutdown() != SECSuccess) {
        exit(1);
    }
    PORT_Free(host);
    FPRINTF(stderr, "detector-probe: exiting with return code %d\n", error);
    PR_Cleanup();
    return error;
}
