/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <windows.h>
#include <windns.h>
#include <wininet.h>
#include "hooking.h"
#include "ntapi.h"
#include "log.h"
#include "pipe.h"

static const char *category = "network";
static IS_SUCCESS_HINTERNET();

HOOKDEF(HRESULT, WINAPI, URLDownloadToFileA,
    LPUNKNOWN pCaller,
    LPCTSTR szURL,
    LPCTSTR szFileName,
    DWORD dwReserved,
    LPVOID lpfnCB
) {
    IS_SUCCESS_HRESULT();

    HRESULT ret = Old_URLDownloadToFileA(pCaller, szURL, szFileName,
        dwReserved, lpfnCB);
    LOQ("ss", "URL", szURL, "FileName", szFileName);
    if(ret == S_OK) {
        pipe("FILE_NEW:%S", szFileName);
    }
    return ret;
}

HOOKDEF(HRESULT, WINAPI, URLDownloadToFileW,
    LPUNKNOWN pCaller,
    LPWSTR szURL,
    LPWSTR szFileName,
    DWORD dwReserved,
    LPVOID lpfnCB
) {
    IS_SUCCESS_HRESULT();

    HRESULT ret = Old_URLDownloadToFileW(pCaller, szURL, szFileName,
        dwReserved, lpfnCB);
    LOQ("uu", "URL", szURL, "FileName", szFileName);
    if(ret == S_OK) {
        pipe("FILE_NEW:%S", szFileName);
    }
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenA,
    _In_  LPCTSTR lpszAgent,
    _In_  DWORD dwAccessType,
    _In_  LPCTSTR lpszProxyName,
    _In_  LPCTSTR lpszProxyBypass,
    _In_  DWORD dwFlags
) {
    HINTERNET ret = Old_InternetOpenA(lpszAgent, dwAccessType, lpszProxyName,
        lpszProxyBypass, dwFlags);
    LOQ("spssp", "Agent", lpszAgent, "AccessType", dwAccessType,
        "ProxyName", lpszProxyName, "ProxyBypass", lpszProxyBypass,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenW,
    _In_  LPWSTR lpszAgent,
    _In_  DWORD dwAccessType,
    _In_  LPWSTR lpszProxyName,
    _In_  LPWSTR lpszProxyBypass,
    _In_  DWORD dwFlags
) {
    HINTERNET ret = Old_InternetOpenW(lpszAgent, dwAccessType, lpszProxyName,
        lpszProxyBypass, dwFlags);
    LOQ("upuup", "Agent", lpszAgent, "AccessType", dwAccessType,
        "ProxyName", lpszProxyName, "ProxyBypass", lpszProxyBypass,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetConnectA,
    _In_  HINTERNET hInternet,
    _In_  LPCTSTR lpszServerName,
    _In_  INTERNET_PORT nServerPort,
    _In_  LPCTSTR lpszUsername,
    _In_  LPCTSTR lpszPassword,
    _In_  DWORD dwService,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_InternetConnectA(hInternet, lpszServerName,
        nServerPort, lpszUsername, lpszPassword, dwService, dwFlags,
        dwContext);
    LOQ("pslsslp", "InternetHandle", hInternet, "ServerName", lpszServerName,
        "ServerPort", nServerPort, "Username", lpszUsername,
        "Password", lpszPassword, "Service", dwService, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetConnectW,
    _In_  HINTERNET hInternet,
    _In_  LPWSTR lpszServerName,
    _In_  INTERNET_PORT nServerPort,
    _In_  LPWSTR lpszUsername,
    _In_  LPWSTR lpszPassword,
    _In_  DWORD dwService,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_InternetConnectW(hInternet, lpszServerName,
        nServerPort, lpszUsername, lpszPassword, dwService, dwFlags,
        dwContext);
    LOQ("puluulp", "InternetHandle", hInternet, "ServerName", lpszServerName,
        "ServerPort", nServerPort, "Username", lpszUsername,
        "Password", lpszPassword, "Service", dwService, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenUrlA,
    __in  HINTERNET hInternet,
    __in  LPCTSTR lpszUrl,
    __in  LPCTSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
) {
    // Disable cache
    //dwFlags |= INTERNET_FLAG_RELOAD;

    HINTERNET ret = Old_InternetOpenUrlA(hInternet, lpszUrl, lpszHeaders,
        dwHeadersLength, dwFlags, dwContext);
    if(dwHeadersLength == (DWORD) -1) dwHeadersLength = strlen(lpszHeaders);
    LOQ("psSp", "ConnectionHandle", hInternet, "URL", lpszUrl,
        "Headers", dwHeadersLength, lpszHeaders, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenUrlW,
    __in  HINTERNET hInternet,
    __in  LPWSTR lpszUrl,
    __in  LPWSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
) {
    // Disable cache
    //dwFlags |= INTERNET_FLAG_RELOAD;

    HINTERNET ret = Old_InternetOpenUrlW(hInternet, lpszUrl, lpszHeaders,
        dwHeadersLength, dwFlags, dwContext);
    LOQ("puUp", "ConnectionHandle", hInternet, "URL", lpszUrl,
        "Headers", dwHeadersLength, lpszHeaders, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, FtpOpenFileA,
    _In_  HINTERNET hConnect,
    _In_  LPCTSTR lpszFileName,
    _In_  DWORD dwAccess,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    // Disable cache
    //dwFlags |= INTERNET_FLAG_RELOAD;

    HINTERNET ret = Old_FtpOpenFileA(hConnect, lpszFileName, dwAccess,
        dwFlags, dwContext);
    LOQ("psll", "InternetHandle", hConnect, "Filename", lpszFileName,
        "Access", dwAccess, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, FtpOpenFileW,
    _In_  HINTERNET hConnect,
    _In_  LPWSTR lpszFileName,
    _In_  DWORD dwAccess,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    // Disable cache
    //dwFlags |= INTERNET_FLAG_RELOAD;
    
    HINTERNET ret = Old_FtpOpenFileW(hConnect, lpszFileName, dwAccess,
        dwFlags, dwContext);
    LOQ("pull", "InternetHandle", hConnect, "Filename", lpszFileName,
        "Access", dwAccess, "Flags", dwFlags);
    return ret;
}

HOOKDEF(BOOL, WINAPI, FtpGetFileA,
    _In_  HINTERNET hConnect,
    _In_  LPCTSTR lpszRemoteFile,
    _In_  LPCTSTR lpszNewFile,
    _In_  BOOL fFailIfExists,
    _In_  DWORD dwFlagsAndAttributes,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_FtpGetFileA(hConnect, lpszRemoteFile, lpszNewFile,
        fFailIfExists, dwFlagsAndAttributes, dwFlags, dwContext);
    LOQ("pssll", "InternetHandle", hConnect, 
        "RemoteFile", lpszRemoteFile, 
        "NewFile", lpszNewFile,
        "FlagsAndAttributes", dwFlagsAndAttributes,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(BOOL, WINAPI, FtpGetFileW,
    _In_  HINTERNET hConnect,
    _In_  LPWSTR lpszRemoteFile,
    _In_  LPWSTR lpszNewFile,
    _In_  BOOL fFailIfExists,
    _In_  DWORD dwFlagsAndAttributes,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_FtpGetFileW(hConnect, lpszRemoteFile, lpszNewFile,
        fFailIfExists, dwFlagsAndAttributes, dwFlags, dwContext);
    LOQ("puull", "InternetHandle", hConnect, 
        "RemoteFile", lpszRemoteFile, 
        "NewFile", lpszNewFile,
        "FlagsAndAttributes", dwFlagsAndAttributes,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(BOOL, WINAPI, FtpPutFileA,
    _In_  HINTERNET hConnect,
    _In_  LPCTSTR lpszLocalFile,
    _In_  LPCTSTR lpszNewRemoteFile,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_FtpPutFileA(hConnect, lpszLocalFile, 
        lpszNewRemoteFile, dwFlags, dwContext);
    LOQ("pssl", "InternetHandle", hConnect, 
        "LocalFile", lpszLocalFile,
        "NewRemoteFile", lpszNewRemoteFile, 
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(BOOL, WINAPI, FtpPutFileW,
    _In_  HINTERNET hConnect,
    _In_  LPWSTR lpszLocalFile,
    _In_  LPWSTR lpszNewRemoteFile,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_FtpPutFileW(hConnect, lpszLocalFile, 
        lpszNewRemoteFile, dwFlags, dwContext);
    LOQ("puul", "InternetHandle", hConnect, 
        "LocalFile", lpszLocalFile,
        "NewRemoteFile", lpszNewRemoteFile, 
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpAddRequestHeadersA,
    _In_  HINTERNET hConnect,
    _In_  LPCTSTR lpszHeaders,
    _In_  DWORD dwHeadersLength,
    _In_  DWORD dwModifiers
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_HttpAddRequestHeadersA(hConnect, lpszHeaders, 
        dwHeadersLength, dwModifiers);
    if(dwHeadersLength == (DWORD) -1) dwHeadersLength = strlen(lpszHeaders);
    LOQ("pSl", "InternetHandle", hConnect, 
        "Headers", dwHeadersLength, lpszHeaders, "Modifiers", dwModifiers);
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpAddRequestHeadersW,
    _In_  HINTERNET hConnect,
    _In_  LPWSTR lpszHeaders,
    _In_  DWORD dwHeadersLength,
    _In_  DWORD dwModifiers
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_HttpAddRequestHeadersW(hConnect, lpszHeaders, 
        dwHeadersLength, dwModifiers);
    LOQ("pUl", "InternetHandle", hConnect, 
        "Headers", dwHeadersLength, lpszHeaders, "Modifiers", dwModifiers);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, HttpOpenRequestA,
    __in  HINTERNET hConnect,
    __in  LPCTSTR lpszVerb,
    __in  LPCTSTR lpszObjectName,
    __in  LPCTSTR lpszVersion,
    __in  LPCTSTR lpszReferer,
    __in  LPCTSTR *lplpszAcceptTypes,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
) {
    // Disable cache
    //dwFlags |= INTERNET_FLAG_RELOAD;

    HINTERNET ret = Old_HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName,
        lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
    LOQ("pssssl", "InternetHandle", hConnect, 
        "Verb", lpszVerb,
        "Path", lpszObjectName,
        "Version", lpszVersion,
        "Referer", lpszReferer,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, HttpOpenRequestW,
    __in  HINTERNET hConnect,
    __in  LPWSTR lpszVerb,
    __in  LPWSTR lpszObjectName,
    __in  LPWSTR lpszVersion,
    __in  LPWSTR lpszReferer,
    __in  LPWSTR *lplpszAcceptTypes,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
) {
    // Disable cache
    //dwFlags |= INTERNET_FLAG_RELOAD;

    HINTERNET ret = Old_HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName,
        lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
    LOQ("puuuul", "InternetHandle", hConnect, 
        "Verb", lpszVerb,
        "Path", lpszObjectName,
        "Version", lpszVersion,
        "Referer", lpszReferer,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpSendRequestA,
    __in  HINTERNET hRequest,
    __in  LPCTSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  LPVOID lpOptional,
    __in  DWORD dwOptionalLength
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength,
        lpOptional, dwOptionalLength);
    if(dwHeadersLength == (DWORD) -1) dwHeadersLength = strlen(lpszHeaders);
    LOQ("pSd", "RequestHandle", hRequest,
        "Headers", dwHeadersLength, lpszHeaders,
        "PostData", dwOptionalLength, lpOptional);
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpSendRequestW,
    __in  HINTERNET hRequest,
    __in  LPWSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  LPVOID lpOptional,
    __in  DWORD dwOptionalLength
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength,
        lpOptional, dwOptionalLength);
    LOQ("pUd", "RequestHandle", hRequest,
        "Headers", dwHeadersLength, lpszHeaders,
        "PostData", dwOptionalLength, lpOptional);
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpSendRequestExA,
    _In_   HINTERNET hRequest,
    _In_   LPINTERNET_BUFFERS lpBuffersIn,
    _Out_  LPINTERNET_BUFFERS lpBuffersOut,
    _In_   DWORD dwFlags,
    _In_   DWORD_PTR dwContext
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_HttpSendRequestExA(hRequest, lpBuffersIn, lpBuffersOut,
        dwFlags, dwContext);
    if (ret) {
        LOQ("pddl", "HttpHandle", hRequest,
            "Headers", lpBuffersIn->dwHeadersLength, lpBuffersIn->lpcszHeader,
            "PostData", lpBuffersIn->dwBufferLength, lpBuffersIn->lpvBuffer,
            "Flags", dwFlags);
    }
    else {
        LOQ("pl", "HttpHandle", hRequest,
            "Flags", dwFlags);
    }
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpSendRequestExW,
    _In_   HINTERNET hRequest,
    _In_   LPINTERNET_BUFFERS lpBuffersIn,
    _Out_  LPINTERNET_BUFFERS lpBuffersOut,
    _In_   DWORD dwFlags,
    _In_   DWORD_PTR dwContext
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_HttpSendRequestExW(hRequest, lpBuffersIn, lpBuffersOut,
        dwFlags, dwContext);
    if (ret) {
        LOQ("pzdl", "HttpHandle", hRequest,
            "Headers", lpBuffersIn->dwHeadersLength, lpBuffersIn->lpcszHeader,
            "PostData", lpBuffersIn->dwBufferLength, lpBuffersIn->lpvBuffer,
            "Flags", dwFlags);
    }
    else {
        LOQ("pl", "HttpHandle", hRequest,
            "Flags", dwFlags);
    }
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpEndRequestA,
    _In_       HINTERNET hRequest,
    _Out_opt_  LPINTERNET_BUFFERS lpBuffersOut,
    _In_       DWORD dwFlags,
    _In_opt_   DWORD_PTR dwContext
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_HttpEndRequestA(hRequest, lpBuffersOut, dwFlags, 
        dwContext);
    LOQ("pl", "HttpHandle", hRequest, 
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpEndRequestW,
    _In_       HINTERNET hRequest,
    _Out_opt_  LPINTERNET_BUFFERS lpBuffersOut,
    _In_       DWORD dwFlags,
    _In_opt_   DWORD_PTR dwContext
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_HttpEndRequestW(hRequest, lpBuffersOut, dwFlags, 
        dwContext);
    LOQ("pl", "HttpHandle", hRequest, 
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpQueryInfoA,
    _In_     HINTERNET hRequest,
    _In_     DWORD dwInfoLevel,
    _Inout_  LPVOID lpvBuffer,
    _Inout_  LPDWORD lpdwBufferLength,
    _Inout_  LPDWORD lpdwIndex
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_HttpQueryInfoA(hRequest, dwInfoLevel, lpvBuffer, 
        lpdwBufferLength, lpdwIndex);
    if (ret) {
        LOQ("plD", "HttpHandle", hRequest,
            "InfoLevel", dwInfoLevel,
            "Buffer", lpdwBufferLength, lpvBuffer);
    }
    else {
        LOQ("pl", "HttpHandle", hRequest,
            "InfoLevel", dwInfoLevel);
    }
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpQueryInfoW,
    _In_     HINTERNET hRequest,
    _In_     DWORD dwInfoLevel,
    _Inout_  LPVOID lpvBuffer,
    _Inout_  LPDWORD lpdwBufferLength,
    _Inout_  LPDWORD lpdwIndex
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_HttpQueryInfoW(hRequest, dwInfoLevel, lpvBuffer, 
        lpdwBufferLength, lpdwIndex);
    if (ret) {
        LOQ("plZ", "HttpHandle", hRequest,
            "InfoLevel", dwInfoLevel,
            "Buffer", lpdwBufferLength, lpvBuffer);
    }
    else {
        LOQ("pl", "HttpHandle", hRequest,
            "InfoLevel", dwInfoLevel);
    }
    return ret;
}

/*
HOOKDEF(DWORD, WINAPI, InternetConfirmZoneCrossing,
    _In_  HWND hWnd,
    _In_  LPTSTR szUrlPrev,
    _In_  LPTSTR szUrlNew,
    _In_  BOOL bPost
) {
    IS_SUCCESS_ZERO();

    DWORD ret = Old_InternetConfirmZoneCrossing(hWnd, szUrlPrev, szUrlNew, 
        bPost);
    LOQ("ss", "UrlPrev", szUrlPrev, "UrlNew", szUrlNew);
    return ret;
}
*/

HOOKDEF(DWORD, WINAPI, InternetConfirmZoneCrossingA,
    _In_  HWND hWnd,
    _In_  LPTSTR szUrlPrev,
    _In_  LPTSTR szUrlNew,
    _In_  BOOL bPost
) {
    IS_SUCCESS_ZERO();

    DWORD ret = Old_InternetConfirmZoneCrossingA(hWnd, szUrlPrev, szUrlNew, 
        bPost);
    LOQ("ss", "UrlPrev", szUrlPrev, "UrlNew", szUrlNew);
    return ret;
}

HOOKDEF(DWORD, WINAPI, InternetConfirmZoneCrossingW,
    _In_  HWND hWnd,
    _In_  LPWSTR szUrlPrev,
    _In_  LPWSTR szUrlNew,
    _In_  BOOL bPost
) {
    IS_SUCCESS_ZERO();

    DWORD ret = Old_InternetConfirmZoneCrossingW(hWnd, szUrlPrev, szUrlNew, 
        bPost);
    LOQ("uu", "UrlPrev", szUrlPrev, "UrlNew", szUrlNew);
    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetReadFile,
    _In_   HINTERNET hFile,
    _Out_  LPVOID lpBuffer,
    _In_   DWORD dwNumberOfBytesToRead,
    _Out_  LPDWORD lpdwNumberOfBytesRead
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead,
        lpdwNumberOfBytesRead);
    LOQ("pD", "InternetHandle", hFile,
        "Buffer", lpdwNumberOfBytesRead, lpBuffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetReadFileExA,
    _In_   HINTERNET hFile,
    _Out_  LPINTERNET_BUFFERS lpBuffersOut,
    _In_   DWORD dwFlags,
    _In_   DWORD_PTR dwContext
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_InternetReadFileExA(hFile, lpBuffersOut, dwFlags, 
        dwContext);
    if (ret) {
        LOQ("pdl", "InternetHandle", hFile,
            //"Headers", lpBuffersOut->dwHeadersLength, lpBuffersOut->lpcszHeader,
            "Buffer", lpBuffersOut->dwBufferLength, lpBuffersOut->lpvBuffer,
            "Flags", dwFlags);
    }
    else {
        LOQ("pl", "InternetHandle", hFile,
            "Flags", dwFlags);
    }
    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetReadFileExW,
    _In_   HINTERNET hFile,
    _Out_  LPINTERNET_BUFFERS lpBuffersOut,
    _In_   DWORD dwFlags,
    _In_   DWORD_PTR dwContext
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_InternetReadFileExW(hFile, lpBuffersOut, dwFlags, 
        dwContext);
    if (ret) {
        LOQ("pdl", "InternetHandle", hFile,
            //"Headers", lpBuffersOut->dwHeadersLength, lpBuffersOut->lpcszHeader,
            "Buffer", lpBuffersOut->dwBufferLength, lpBuffersOut->lpvBuffer,
            "Flags", dwFlags);
    }
    else {
        LOQ("pl", "InternetHandle", hFile,
            "Flags", dwFlags);
    }
    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetWriteFile,
    _In_   HINTERNET hFile,
    _In_   LPCVOID lpBuffer,
    _In_   DWORD dwNumberOfBytesToWrite,
    _Out_  LPDWORD lpdwNumberOfBytesWritten
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_InternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite,
        lpdwNumberOfBytesWritten);
    LOQ("pD", "InternetHandle", hFile,
        "Buffer", lpdwNumberOfBytesWritten, lpBuffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetCloseHandle,
    _In_  HINTERNET hInternet
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_InternetCloseHandle(hInternet);
    LOQ("p", "InternetHandle", hInternet);
    return ret;
}

HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_A,
    __in         PCSTR lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
) {
    IS_SUCCESS_ZERO();

    DNS_STATUS ret = Old_DnsQuery_A(lpstrName, wType, Options, pExtra,
        ppQueryResultsSet, pReserved);
    LOQ("sil", "Name", lpstrName, "Type", wType, "Options", Options);
    return ret;
}

HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_UTF8,
    __in         LPBYTE lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
) {
    IS_SUCCESS_ZERO();

    DNS_STATUS ret = Old_DnsQuery_UTF8(lpstrName, wType, Options, pExtra,
        ppQueryResultsSet, pReserved);
    LOQ("sil", "Name", lpstrName, "Type", wType, "Options", Options);
    return ret;
}

HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_W,
    __in         PWSTR lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
) {
    IS_SUCCESS_ZERO();

    DNS_STATUS ret = Old_DnsQuery_W(lpstrName, wType, Options, pExtra,
        ppQueryResultsSet, pReserved);
    LOQ("uil", "Name", lpstrName, "Type", wType, "Options", Options);
    return ret;
}

HOOKDEF(int, WINAPI, getaddrinfo,
    _In_opt_  PCSTR pNodeName,
    _In_opt_  PCSTR pServiceName,
    _In_opt_  const ADDRINFOA *pHints,
    _Out_     PADDRINFOA *ppResult
) {
    IS_SUCCESS_ZERO();

    BOOL ret = Old_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    LOQ("ss", "NodeName", pNodeName, "ServiceName", pServiceName);
    return ret;
}

HOOKDEF(int, WINAPI, GetAddrInfoW,
    _In_opt_  PCWSTR pNodeName,
    _In_opt_  PCWSTR pServiceName,
    _In_opt_  const ADDRINFOW *pHints,
    _Out_     PADDRINFOW *ppResult
) {
    IS_SUCCESS_ZERO();

    BOOL ret = Old_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    LOQ("uu", "NodeName", pNodeName, "ServiceName", pServiceName);
    return ret;
}
