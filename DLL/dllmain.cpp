// dllmain.cpp : Defines the entry point for the DLL application.

#include "pch.h"
#include "fileapi.h"
#include "detours.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <strsafe.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment(lib, "detours.lib")

#define WIN32_LEAN_AND_MEAN
#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

// function for printing debug massages with format string
#define DBGPRINT(kwszDebugFormatString, ...) _DBGPRINT(__FUNCTIONW__, __LINE__, kwszDebugFormatString, __VA_ARGS__)
VOID _DBGPRINT(LPCWSTR kwszFunction, INT iLineNumber, LPCWSTR kwszDebugFormatString, ...);

//Prototypes
HANDLE(WINAPI* pFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) = FindFirstFileA;
HANDLE WINAPI MyFindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
HANDLE(WINAPI* pFindFirstFileW)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) = FindFirstFileW;
HANDLE WINAPI MyFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
BOOL(WINAPI* pFindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) = FindNextFileA;
BOOL WINAPI MyFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
BOOL(WINAPI* pFindNextFileW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) = FindNextFileW;
BOOL WINAPI MyFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
HANDLE(WINAPI* pCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileA;
HANDLE WINAPI MyCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE(WINAPI* pCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileW;
HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

// Returns pointer to allocated wstr with content of non_wide_str
wchar_t* regular_to_wide_str(char* non_wide_str);
// Detours function with fucn_name or hide file if "hide" passed
int DetourFunction(const char* func_name);
// Send to monitor info about function call: name of function, date and time
void send_func_call_log(const char* func_name);
// Start server
int start_server();
// recieve parameters from program
int recieve_parameters();
// close connection
void close_connection();


// path to file to hide
char hide_file_path[DEFAULT_BUFLEN] = { 0 };
wchar_t* hide_file_path_w;

// parameters
char param[DEFAULT_BUFLEN] = { 0 };

// for server-client connection
WSADATA wsaData;
int iResult;
SOCKET ListenSocket = INVALID_SOCKET;
SOCKET ClientSocket = INVALID_SOCKET;
struct addrinfo* result = NULL;
struct addrinfo hints;
char recvbuf[DEFAULT_BUFLEN];
int recvbuflen = DEFAULT_BUFLEN;



// Main function
BOOL APIENTRY DllMain( HMODULE hDLL,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH: //Do standard detouring
        {
            // start connection and recieve parameters
            if (start_server() == 1)
                DBGPRINT(L"start_server() fail");
            if (recieve_parameters() == 1)
                DBGPRINT(L"recieve_parameters() fail");
            
            // analize parameters
            char* token = strtok(param, " ");
            if (strncmp(token, "--func", 6) == 0)
            {
                DBGPRINT(L"--func parameter");
                token = strtok(NULL, " "); // get name of function

                // Detour function to monitor calls
                DisableThreadLibraryCalls(hDLL); // disable the DLL_THREAD_ATTACH and DLL_THREAD_DETACH notification calls
                if (DetourFunction(token) == 0)
                    DBGPRINT(L"DetourFunction() success, wait for logs");
                else 
                {
                    DBGPRINT(L"DetourFunction() fail");
                    close_connection();
                }
            }
            else if (strncmp(token, "--hide", 6) == 0)
            {
                DBGPRINT(L"--hide parameter");
                token = strtok(NULL, " ");
                
                // save path to file to hide into variables hide_file_path and hide_file_path_w
                strcpy(hide_file_path, token);
                hide_file_path_w = regular_to_wide_str(hide_file_path);
                DBGPRINT(L"Path to hidden file: %s", hide_file_path_w);

                // Detour functions so they cannot see file
                DisableThreadLibraryCalls(hDLL);
                if (DetourFunction("hide") == 0) // "hide" as argument to DetourFunction() detours all functions
                {
                    DBGPRINT(L"DetourFunction() success, wait for logs");
                }
                else
                {
                    DBGPRINT(L"DetourFunction() fail");
                    close_connection();
                }
            }
            else
            {
                DBGPRINT(L"no --hide or --func parameter");
            }
            break;
        }
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

wchar_t* regular_to_wide_str(char* non_wide_str)
{
    int nChars = MultiByteToWideChar(CP_ACP, 0, non_wide_str, -1, NULL, 0);
    wchar_t* wide_str = new wchar_t[nChars];
    MultiByteToWideChar(CP_ACP, 0, non_wide_str, -1, (LPWSTR)wide_str, nChars);
    return wide_str;
}

int start_server()
{
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        DBGPRINT(L"WSAStartup() failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        DBGPRINT(L"getaddrinfo() failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for the server to listen for client connections.
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        DBGPRINT(L"socket() failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        DBGPRINT(L"bind() failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        DBGPRINT(L"listen() failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        DBGPRINT(L"accept() failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // No longer need server socket
    closesocket(ListenSocket);
    return 0;
}

int recieve_parameters()
{
    //  recieve parameters
    iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
    if (iResult > 0)
    {
        DBGPRINT(L"parameters recieved");
    }
    else if (iResult == 0)
    {
        DBGPRINT(L"parameters not recieved, connection closed");
        return 1;
    }
    else
    {
        DBGPRINT(L"recv() failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // copy to param variable
    int recv_param_len = iResult;
    strncpy_s(param, DEFAULT_BUFLEN, recvbuf, recv_param_len);
}

void close_connection()
{
    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        DBGPRINT(L"shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
    }

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();
}

void send_func_call_log(const char* func_name)
{
    CHAR send_msg[DEFAULT_BUFLEN] = { 0 };
    SYSTEMTIME st;
    GetLocalTime(&st);
    sprintf_s(send_msg, "%d-%02d-%02d %02d:%02d:%02d:%03d : %s()\n\0", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, func_name);
    int iSendResult = send(ClientSocket, send_msg, strlen(send_msg) + 1, 0);
    if (iSendResult == SOCKET_ERROR) {
        DBGPRINT(L"send() failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
    }
}

int DetourFunction(const char* func_name)
{
    if (strncmp(func_name, "FindFirstFile", 13) == 0)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindFirstFileA, MyFindFirstFileA);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"FindFirstFileA() detoured successfully");
        else
            DBGPRINT(L"FindFirstFileA() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindFirstFileW, MyFindFirstFileW);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"FindFirstFileW() detoured successfully");
        else
            DBGPRINT(L"FindFirstFileW() detour fail");
        return 0;
    }
    else if (strncmp(func_name, "FindNextFile", 12) == 0)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindNextFileA, MyFindNextFileA);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"FindNextFileA() detoured successfully");
        else
            DBGPRINT(L"FindNextFileA() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindNextFileW, MyFindNextFileW);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"FindNextFileW() detoured successfully");
        else
            DBGPRINT(L"FindNextFileW() detour fail");
        return 0;
    }
    else if (strncmp(func_name, "CreateFile", 10) == 0)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pCreateFileA, MyCreateFileA);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"MyCreateFileA() detoured successfully");
        else
            DBGPRINT(L"MyCreateFileA() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pCreateFileW, MyCreateFileW);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"MyCreateFileW() detoured successfully");
        else
            DBGPRINT(L"MyCreateFileW() detour fail");
        return 0;
    }
    else if (strncmp(func_name, "hide", 4) == 0) // detour all funcs
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindFirstFileA, MyFindFirstFileA);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"FindFirstFileA() detoured successfully");
        else
            DBGPRINT(L"FindFirstFileA() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindFirstFileW, MyFindFirstFileW);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"FindFirstFileW() detoured successfully");
        else
            DBGPRINT(L"FindFirstFileW() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindNextFileA, MyFindNextFileA);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"FindNextFileA() detoured successfully");
        else
            DBGPRINT(L"FindNextFileA() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindNextFileW, MyFindNextFileW);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"FindNextFileW() detoured successfully");
        else
            DBGPRINT(L"FindNextFileW() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pCreateFileA, MyCreateFileA);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"MyCreateFileA() detoured successfully");
        else
            DBGPRINT(L"MyCreateFileA() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pCreateFileW, MyCreateFileW);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"MyCreateFileW() detoured successfully");
        else
            DBGPRINT(L"MyCreateFileW() detour fail");
        return 0;
    }
    else
        return 1;
}

HANDLE WINAPI MyFindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
    DBGPRINT(L"In MyFindFirstFileA");
    send_func_call_log("FindFirstFileA");
    if (strcmp(hide_file_path, lpFileName) == 0) // if arg to func is hidden file
        return INVALID_HANDLE_VALUE;
    return pFindFirstFileA(lpFileName, lpFindFileData);
}

HANDLE WINAPI MyFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
{
    DBGPRINT(L"In MyFindFirstFileW");
    send_func_call_log("FindFirstFileW");
    if (hide_file_path_w != NULL && wcscmp(hide_file_path_w, lpFileName) == 0) // if arg to func is hidden file
        return INVALID_HANDLE_VALUE;
    return pFindFirstFileW(lpFileName, lpFindFileData);
}

BOOL WINAPI MyFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
    DBGPRINT(L"In MyFindNextFileA");
    send_func_call_log("FindNextFileA");
    if (strcmp(lpFindFileData->cFileName, hide_file_path) == 0) // if arg to func is hidden file
        strcpy(lpFindFileData->cFileName, "nonexistent.nonexistent"); // make fake argument
    return pFindNextFileA(hFindFile, lpFindFileData);
}

BOOL WINAPI MyFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
    DBGPRINT(L"In MyFindNextFileW");
    send_func_call_log("FindNextFileW");
    if (hide_file_path_w != NULL && wcscmp(lpFindFileData->cFileName, hide_file_path_w) == 0) // if arg to func is hidden file
        wcscpy(lpFindFileData->cFileName, L"nonexistent.nonexistent"); // make fake argument
    return pFindNextFileW(hFindFile, lpFindFileData);
}

HANDLE WINAPI MyCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    DBGPRINT(L"In MyCreateFileA");
    send_func_call_log("CreateFileA");
    if (strcmp(lpFileName, hide_file_path) == 0) // if arg to func is hidden file
        return INVALID_HANDLE_VALUE;
    return pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    DBGPRINT(L"In MyCreateFileW");
    send_func_call_log("CreateFileW");
    if (hide_file_path_w != NULL && wcscmp(lpFileName, hide_file_path_w) == 0) // if arg to func is hidden file
        return INVALID_HANDLE_VALUE;
    return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

VOID _DBGPRINT(LPCWSTR kwszFunction, INT iLineNumber, LPCWSTR kwszDebugFormatString, ...)
{
    INT cbFormatString = 0;
    va_list args;
    PWCHAR wszDebugString = NULL;
    size_t st_Offset = 0;

    va_start(args, kwszDebugFormatString);

    cbFormatString = _scwprintf(L"[%s:%d] ", kwszFunction, iLineNumber) * sizeof(WCHAR);
    cbFormatString += _vscwprintf(kwszDebugFormatString, args) * sizeof(WCHAR) + 2;

    /* Depending on the size of the format string, allocate space on the stack or the heap. */
    wszDebugString = (PWCHAR)_malloca(cbFormatString);

    /* Populate the buffer with the contents of the format string. */
    StringCbPrintfW(wszDebugString, cbFormatString, L"[%s:%d] ", kwszFunction, iLineNumber);
    StringCbLengthW(wszDebugString, cbFormatString, &st_Offset);
    StringCbVPrintfW(&wszDebugString[st_Offset / sizeof(WCHAR)], cbFormatString - st_Offset, kwszDebugFormatString, args);

    OutputDebugStringW(wszDebugString);

    _freea(wszDebugString);
    va_end(args);
}