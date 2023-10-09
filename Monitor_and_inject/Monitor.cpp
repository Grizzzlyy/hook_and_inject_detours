#include <winsock2.h>
#include <iostream>
#include <string>
#include <ShlObj.h>
#include <tlhelp32.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define WIN32_LEAN_AND_MEAN
#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

using std::string;

// path to dll to inject
LPCWSTR injectLibraryPath = L"C:\\Users\\user\\Downloads\\TRSPO\\Lab1\\dll_proj\\x64\\Release\\dll_proj.dll";

void print_usage();
// finds first process with proc_name and return its PID
int get_process_pid_by_name(const char* proc_name);
//inject dll to process with targetPID
void inject_dll(DWORD targetPID);
// send parameters to server (to dll code)
int send_parameters(char* argv[]);

int main(int argc, char* argv[])
{
    // check admin rights and number of arguments
    if (!IsUserAnAdmin())
    {
        std::cout << "Administrator privileges required" << std::endl;
        return 1;
    }
    if (argc != 5)
    {
        std::cout << "Uncorrect number of arguments!" << std::endl;
        print_usage();
        return 1;
    }

    // check argv
    DWORD targetPID;
    if (strncmp(argv[1], "--pid", 5) == 0)
    {
        targetPID = atoi(argv[2]);
        if (strncmp(argv[3], "--func", 6) == 0 || strncmp(argv[3], "--hide", 6) == 0)
        {
            inject_dll(targetPID);
            std::cout << "Looks like DLL injected to process " << targetPID << std::endl;
            send_parameters(argv);
        }
        else
        {
            std::cout << "wrong arguments" << std::endl;
            print_usage();
            return 1;
        }
    }
    else if (strncmp(argv[1], "--name", 6) == 0)
    {
        targetPID = get_process_pid_by_name(argv[2]);
        if (targetPID == 0) {
            std::cout << "can't find process with name " << argv[2] << std::endl;
            return 1;
        }

        if (strncmp(argv[3], "--func", 6) == 0 || strncmp(argv[3], "--hide", 6) == 0)
        {
            inject_dll(targetPID);
            std::cout << "Looks like DLL injected to process " << targetPID << std::endl;
            if (send_parameters(argv) == 1)
                printf("send_parameters() fail");
        }
        else
        {
            std::cout << "wrong arguments" << std::endl;
            print_usage();
            return 1;
        }
    }
    else
    {
        std::cout << "wrong arguments" << std::endl;
        print_usage();
        return 1;
    }

    return 0;
}

void print_usage()
{
    std::cout << "Usage:" << std::endl;
    std::cout << "1) injector_proj.exe --pid <pid> --func <func_name>" << std::endl;
    std::cout << "2) injector_proj.exe --pid <pid> --hide <path_to_file>" << std::endl;
    std::cout << "3) injector_proj.exe --name <proc_name> --func <func_name>" << std::endl;
    std::cout << "4) injector_proj.exe --name <proc_name> --hide <path_to_file>" << std::endl;
}

int get_process_pid_by_name(const char* proc_name)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            int nChars = MultiByteToWideChar(CP_ACP, 0, proc_name, -1, NULL, 0);
            wchar_t* proc_name_w = new wchar_t[nChars];
            MultiByteToWideChar(CP_ACP, 0, proc_name, -1, (LPWSTR)proc_name_w, nChars);
            if (wcscmp(entry.szExeFile, proc_name_w) == 0)
            {
                delete[] proc_name_w;
                return entry.th32ProcessID;
            }
            delete[] proc_name_w;
        }
    }
    return 0;
}

void inject_dll(DWORD targetPID)
{
    HANDLE targetProcessHandle = OpenProcess(
        PROCESS_ALL_ACCESS, // rights
        FALSE, //dont inherit handles
        targetPID); //PID of target process
    if (targetProcessHandle == NULL)
    {
        printf("OpenProcess() fail\n");
    }
    // How many bytes we need to hold the whole DLL path
    int bytesToAlloc = (1 + lstrlenW(injectLibraryPath)) * sizeof(WCHAR);

    // Allocate memory in the remote process for the DLL path
    LPWSTR remoteBufferForLibraryPath = LPWSTR(VirtualAllocEx(
        targetProcessHandle, NULL, bytesToAlloc, MEM_COMMIT, PAGE_READWRITE));
    // Put the DLL path into the address space of the target process
    WriteProcessMemory(targetProcessHandle, remoteBufferForLibraryPath,
        injectLibraryPath, bytesToAlloc, NULL);
    // Get the real address of LoadLibraryW in Kernel32.dll
    PTHREAD_START_ROUTINE loadLibraryFunction = PTHREAD_START_ROUTINE(
        GetProcAddress(GetModuleHandleW(L"Kernel32"), "LoadLibraryW"));

    // Create remote thread that calls LoadLibraryW
    HANDLE remoteThreadHandle = CreateRemoteThread(targetProcessHandle,
        NULL, 0, loadLibraryFunction, remoteBufferForLibraryPath, 0, NULL);
    if (remoteThreadHandle == NULL)
        printf("InjectDll: CreateRemoteThread failed. Line = %d, GetLastError = %d\n",
            __LINE__, GetLastError());
}

int send_parameters(char* argv[])
{
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL,
        * ptr = NULL,
        hints;
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;
    char* sendbuf = (char*)calloc(DEFAULT_BUFLEN, sizeof(char));

    // copy parameters to sendbuf
    strcat_s(sendbuf, DEFAULT_BUFLEN, argv[3]);
    strcat_s(sendbuf, DEFAULT_BUFLEN, " ");
    strcat_s(sendbuf, DEFAULT_BUFLEN, argv[4]);

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo("localhost", DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }

    // Send an initial buffer (parameters)
    iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // Receive until the peer closes the connection (recieve log messages about function calls)
    std::cout << "Waiting for server messages" << std::endl;
    do {

        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0)
            printf(recvbuf);
        else if (iResult == 0)
            printf("Connection closed\n");
        else
            printf("recv failed with error: %d\n", WSAGetLastError());

    } while (iResult > 0);

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}