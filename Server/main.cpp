/*
* SOCKET CHATROOM SERVER
* Copyright ©GUOBAJUN 2022
* USE TCP/IPv4
*/

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif // !WIN32_LEAN_AND_MEAN  解决历史遗留问题，防止冲突

#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <set>
#include <map>


#define ServerPort "10086"
#define DEFAULT_BUFLEN 4096
#define UserNameLen 512

#pragma comment(lib, "Ws2_32.lib")

using std::cin;
using std::cout;
using std::cerr;
using std::endl;
using std::map;
using std::set;
using std::string;

struct SocketInfo {
	SOCKET Sockfd;
	CHAR servstr[NI_MAXSERV];
	SocketInfo(SOCKET Sock, CHAR serv[NI_MAXSERV]) {
		Sockfd = Sock;
		strcpy_s(servstr, serv);
	}
}; // 为ChatThread提供丰富信息

struct CmdInfo {
	string cmd;
	SOCKET ChatSocket;
	CmdInfo() { cmd = ""; ChatSocket = INVALID_SOCKET; }
}; // 为CmdCheck提供解析结果存储

map<string, SOCKET> ClientNameTransfer; // 用户名到Socket映射
map<INT, string> ClientPortTransfer;    // 用户端口到用户名映射
map<SOCKET, SOCKET> ChatSockets;    // 客户端P2P映射
set<SOCKET> LinkToServer;               // 连接到Server的Socket

DWORD WINAPI ServerThread(LPVOID lpParam); // 为每一个客户端提供连接线程
DWORD WINAPI ChatThread(LPVOID lpParam);   // 为每一个客户端提供聊天线程
DWORD WINAPI CmdCheck(CHAR* Txt);          // 检查客户端是否发送服务器命令
CmdInfo WINAPI CmdCommit(CHAR* Txt);       // 执行来自客户端的命令


INT main()
{
	WSADATA wsaData;
	INT iResult;
	addrinfo* results = NULL, * ptr = NULL, hints;
	SOCKET* ServerSockets = NULL; // 供服务器侦听客户端连接
	HANDLE* ServerThreads = NULL;
	CHAR hoststr[NI_MAXHOST], servstr[NI_MAXSERV];
	INT socket_count = 0;

	ClientNameTransfer[(string)"Server"] = INVALID_SOCKET; // 为Server提供名称映射

	cout << "Server initing..." << endl;

	// 初始化Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		cerr << "WSAStartup failed with Code " << iResult << endl;
		WSACleanup();
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;       // IPv4
	hints.ai_socktype = SOCK_STREAM; // 流套接字
	hints.ai_protocol = IPPROTO_TCP; // TCP协议
	hints.ai_flags = AI_PASSIVE;     // 调用方打算在对 绑定 函数的调用中使用返回的套接字地址结构

	iResult = getaddrinfo(NULL, ServerPort, &hints, &results);
	if (iResult != 0) {
		cerr << "getaddrinfo failed with Code " << iResult << endl;
		WSACleanup();
		return 1;
	}

	if (results == NULL) {
		cerr << "Server could not be resolved" << endl;
		WSACleanup();
		return 1;
	}

	// 统计连接类型数量
	ptr = results;
	while (ptr) {
		socket_count++;
		ptr = ptr->ai_next;
	}


	// 申请服务Socket空间
	ServerSockets = (SOCKET*)HeapAlloc(GetProcessHeap(),
		HEAP_ZERO_MEMORY, sizeof(SOCKET) * socket_count);
	if (ServerSockets == NULL) {
		cerr << "HeapAlloc failed with Code: " << GetLastError() << endl;
		freeaddrinfo(results);
		WSACleanup();
		return 1;
	}

	// 初始化服务Socket序列
	for (INT i = 0; i < socket_count; i++)
		ServerSockets[i] = INVALID_SOCKET;

	cout << "Server up!!!" << endl;

	//创建服务Socket
	socket_count = 0;
	ptr = results;
	while (ptr) {
		ServerSockets[socket_count] = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol); // 为服务器创建Socket
		if (ServerSockets[socket_count] == INVALID_SOCKET) {
			for (INT i = 0; i < socket_count; i++)
			{
				if (ServerSockets[i] != INVALID_SOCKET)
					closesocket(ServerSockets[i]);
				ServerSockets[i] = INVALID_SOCKET;
			}
			HeapFree(GetProcessHeap(), 0, ServerSockets);
			ServerSockets = NULL;
			freeaddrinfo(results);
			WSACleanup();
			return 1;
		}


		iResult = bind(ServerSockets[socket_count], ptr->ai_addr, (INT)ptr->ai_addrlen); // 将服务器Socket绑定到端口
		if (iResult == SOCKET_ERROR) {
			cerr << "bind failed with Code: " << WSAGetLastError() << endl;
			for (INT i = 0; i < socket_count; i++)
			{
				if (ServerSockets[i] != INVALID_SOCKET)
					closesocket(ServerSockets[i]);
				ServerSockets[i] = INVALID_SOCKET;
			}
			HeapFree(GetProcessHeap(), 0, ServerSockets);
			ServerSockets = NULL;
			freeaddrinfo(results);
			WSACleanup();
			return 1;
		}

		iResult = listen(ServerSockets[socket_count], SOMAXCONN); // 服务器开始侦听是否有客户端连接，单Socket允许连接数设为最大值
		if (iResult == SOCKET_ERROR) {
			cerr << "listen failed with Code: " << WSAGetLastError() << endl;
			for (INT i = 0; i < socket_count; i++)
			{
				if (ServerSockets[i] != INVALID_SOCKET)
					closesocket(ServerSockets[i]);
				ServerSockets[i] = INVALID_SOCKET;
			}
			HeapFree(GetProcessHeap(), 0, ServerSockets);
			ServerSockets = NULL;
			freeaddrinfo(results);
			WSACleanup();
			return 1;
		}

		//for log 获取服务器Socket的端口信息
		iResult = getnameinfo(ptr->ai_addr, (socklen_t)ptr->ai_addrlen, hoststr, NI_MAXHOST, servstr, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
		if (iResult != 0) {
			cerr << "getnameinfo failed with Code: " << iResult << endl;
			for (INT i = 0; i < socket_count; i++)
			{
				if (ServerSockets[i] != INVALID_SOCKET)
					closesocket(ServerSockets[i]);
				ServerSockets[i] = INVALID_SOCKET;
			}
			HeapFree(GetProcessHeap(), 0, ServerSockets);
			ServerSockets = NULL;
			freeaddrinfo(results);
			WSACleanup();
			return 1;
		}

		cout << "socket " << ServerSockets[socket_count] << " bound to address " << hoststr << " and port " << servstr << endl;
		socket_count++;
		ptr = ptr->ai_next;
	}

	// 申请线程空间
	ServerThreads = (HANDLE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HANDLE) * socket_count);
	if (ServerThreads == NULL) {
		cerr << "HeapAlloc failed with Code: " << GetLastError() << endl;
		WSACleanup();
		return 1;
	}

	// 创建线程
	for (INT i = 0; i < socket_count; i++) {
		ServerThreads[i] = CreateThread(NULL, 0, ServerThread, (LPVOID)ServerSockets[i], 0, NULL);
		if (ServerThreads[i] == NULL) {
			cerr << "CreateThread failed with Code: " << GetLastError() << endl;
			WSACleanup();
			return 1;
		}
	}


	// 等待所有会话结束
	iResult = WaitForMultipleObjects(socket_count, ServerThreads, TRUE, INFINITE);
	if ((iResult == WAIT_FAILED) || (iResult == WAIT_TIMEOUT)) {
		cerr << "WaitForMultipleObjects failed with Code: " << GetLastError() << endl;
		WSACleanup();
		return 1;
	}

	WSACleanup();
	return 0;
}

/*
* ServerThread：为每个服务器Socket提供线程
* 参数：服务器Socket
*/
DWORD WINAPI ServerThread(LPVOID lpParam)
{
	SOCKET ServerSocket, ClientSocket = INVALID_SOCKET;
	SOCKADDR_STORAGE from;
	CHAR servstr[NI_MAXSERV], hoststr[NI_MAXHOST];
	INT iResult, fromLen, socketType;

	// 接收Socket参数
	ServerSocket = (SOCKET) lpParam;
	fromLen = sizeof(socketType);
	iResult = getsockopt(ServerSocket, SOL_SOCKET, SO_TYPE, (CHAR*)&socketType, &fromLen);
	if (iResult == INVALID_SOCKET) {
		cerr << "getsockopt(SO_TYPE) failed with Code: " << WSAGetLastError() << endl;
		WSACleanup();
		return 1;
	}

	while (true) {
		fromLen = sizeof(from);
		ClientSocket = accept(ServerSocket, (sockaddr*)&from, &fromLen); // 接受来自的客户端连接
		if (ClientSocket == SOCKET_ERROR) {
			cerr << "accept failed with Code: " << WSAGetLastError() << endl;
			return 1;
		}
		// 获取客户端信息
		iResult = getnameinfo((SOCKADDR*)&from, fromLen, hoststr, NI_MAXHOST, servstr, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
		if (iResult != 0) {
			cerr << "getnameinfo failed with Code: " << WSAGetLastError() << endl;
			continue;
		}
		cout << "Accepted connection form host " << hoststr << " and port " << servstr << endl;
		// 打包客户端信息，发送到聊天线程
		SocketInfo* ClientInfo = new SocketInfo(ClientSocket, servstr);
		HANDLE hChatThread;
		hChatThread = CreateThread(NULL, 0, ChatThread, (LPVOID)ClientInfo, 0, NULL);
		if (hChatThread == NULL) {
			cerr << "CreateThread for ChatThread failed with Code: " << GetLastError() << endl;
			closesocket(ClientSocket);
			continue;
		}
		CloseHandle(hChatThread);
	}
	return 0;
}


/*
* ChatThread：为每个客户端提供信息收发服务
* 参数：SocketInfo 包含客户端Socket和客户端端口号
*/
DWORD WINAPI ChatThread(LPVOID lpParam)
{
	SocketInfo ClientInfo = *(SocketInfo*)lpParam;
	SOCKET ClientSocket = ClientInfo.Sockfd;
	string UserName, ChatTxt;
	CHAR Buffer[DEFAULT_BUFLEN];
	INT byteCount;
	INT iResult;
	CmdInfo CmdResult;

	//获取用户信息
	if (ClientSocket != INVALID_SOCKET) {
		byteCount = recv(ClientSocket, Buffer, DEFAULT_BUFLEN, 0); // 检查是否可以正常接
		if (byteCount == SOCKET_ERROR) {
			iResult = WSAGetLastError();
			cerr << "recv failed with Code: " << iResult << endl;
			if (iResult == 10054)
				cerr << "Client form port " << ClientInfo.servstr << " exited unexpectly" << endl;
			closesocket(ClientSocket);
			return 1;
		}
		if (strcmp(Buffer, "Server") == 0) { // 用户不能取名叫Server
			cerr << "Client form port " << ClientInfo.servstr << " is blocked" << endl;
			shutdown(ClientSocket, SD_SEND);
			return 1;
		}
		// 将连接用户的名字与Socket和端口关联
		UserName = Buffer;
		ChatSockets[ClientSocket] = INVALID_SOCKET;              // 初始化聊天对象
		ClientNameTransfer[UserName] = ClientSocket;
		ClientPortTransfer[atoi(ClientInfo.servstr)] = UserName; // 建立映射
		LinkToServer.insert(ClientSocket);                       // 将连接信息加入服务器统计

		cout << "read " << byteCount << " bytes" << endl;
		byteCount = send(ClientSocket, Buffer, byteCount, 0);
		if (byteCount == SOCKET_ERROR) {
			iResult = WSAGetLastError();
			cerr << "send failed with Code: " << iResult << endl;
			ClientNameTransfer.erase(UserName);
			ClientPortTransfer.erase(atoi(ClientInfo.servstr));
			ChatSockets.erase(ClientSocket);
			LinkToServer.erase(ClientSocket);// 断开连接需要清理旧的映射信息.
			closesocket(ClientSocket);
			return 1;
		}
		cout << "wrote " << byteCount << " bytes" << endl;
	}

	// 持续通信
	while (ClientSocket != INVALID_SOCKET) {
		byteCount = recv(ClientSocket, Buffer, DEFAULT_BUFLEN, 0);
		if (byteCount == SOCKET_ERROR) { // 通信错误
			iResult = WSAGetLastError();
			cerr << "recv failed with Code: " << iResult << endl;
			if (iResult == 10054)
				cerr << ClientPortTransfer[atoi(ClientInfo.servstr)] << " form port " << ClientInfo.servstr << " exited unexpectly" << endl;
			ClientNameTransfer.erase(UserName);
			ClientPortTransfer.erase(atoi(ClientInfo.servstr));
			if (ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
			{
				send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
				ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
			}
			ChatSockets.erase(ClientSocket);
			LinkToServer.erase(ClientSocket);// 断开连接需要清理旧的映射信息.
			closesocket(ClientSocket);
			return 1;
		}
		else if (byteCount == 0) { // 通信结束
			iResult = shutdown(ClientSocket, SD_SEND);
			if (iResult == SOCKET_ERROR) {
				cerr << "shutdown failed with Code: " << WSAGetLastError() << endl;
				ClientNameTransfer.erase(UserName);
				ClientPortTransfer.erase(atoi(ClientInfo.servstr));
				if (ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
				{
					send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
					ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
				}
				ChatSockets.erase(ClientSocket);
				LinkToServer.erase(ClientSocket);// 断开连接需要清理旧的映射信息.
				closesocket(ClientSocket);
				return 1;
			}
			cout << ClientPortTransfer[atoi(ClientInfo.servstr)] << " from Port " << ClientInfo.servstr << " exited successfully" << endl;
			ClientNameTransfer.erase(UserName);
			ClientPortTransfer.erase(atoi(ClientInfo.servstr));
			if (ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
			{
				send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
				ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
			}
			ChatSockets.erase(ClientSocket);
			LinkToServer.erase(ClientSocket);// 断开连接需要清理旧的映射信息.
			closesocket(ClientSocket);
			ClientSocket = INVALID_SOCKET;
		}
		else {
			cout << "read " << byteCount << " bytes" << endl;
			if (CmdCheck(Buffer)) { // 检查是否是来自客户端的命令
				CmdResult = CmdCommit(Buffer);
				if (CmdResult.cmd == "sendto") { // redirect命令
					if (CmdResult.ChatSocket != INVALID_SOCKET)
					{
						if (ChatSockets[CmdResult.ChatSocket] != INVALID_SOCKET) { // 聊天占线
							byteCount = send(ClientSocket, "Your friend is chatting with other people.", 43, 0);
							if (byteCount == SOCKET_ERROR) {
								iResult = WSAGetLastError();
								cerr << "recv failed with Code: " << iResult << endl;
								if (iResult == 10054)
									cerr << ClientPortTransfer[atoi(ClientInfo.servstr)] << " form port " << ClientInfo.servstr << " exited unexpectly" << endl;
								ClientNameTransfer.erase(UserName);
								ClientPortTransfer.erase(atoi(ClientInfo.servstr));
								if (ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
								{
									send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
									ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
								}
								ChatSockets.erase(ClientSocket);
								LinkToServer.erase(ClientSocket);// 断开连接需要清理旧的映射信息.
								closesocket(ClientSocket);
								return 1;
							}
							continue;
						}
						if (ClientSocket == CmdResult.ChatSocket) {  // 重定向到自己
							if (ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
							{
								send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
								ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
							}
							ChatSockets[ClientSocket] = CmdResult.ChatSocket;
							send(ClientSocket, "Server: Redirected Successfully!", 33, 0);
							continue;
						}
						ChatSockets[ClientSocket] = CmdResult.ChatSocket;
						sprintf_s(Buffer, DEFAULT_BUFLEN, "Server: %s connected with You!", ClientPortTransfer[atoi(ClientInfo.servstr)].c_str());
						byteCount = send(ChatSockets[ClientSocket], Buffer, (INT)strlen(Buffer) + 1, 0);
						if (byteCount == SOCKET_ERROR) {
							iResult = WSAGetLastError();
							cerr << "recv failed with Code: " << iResult << endl;
							if (iResult == 10054)
								cerr << ClientPortTransfer[atoi(ClientInfo.servstr)] << " form port " << ClientInfo.servstr << " exited unexpectly" << endl;
							ClientNameTransfer.erase(UserName);
							ClientPortTransfer.erase(atoi(ClientInfo.servstr));
							if (ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
							{
								send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
								ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
							}
							ChatSockets.erase(ClientSocket);
							LinkToServer.erase(ClientSocket);// 断开连接需要清理旧的映射信息.
							closesocket(ClientSocket);
							return 1;
						}
						ChatSockets[ChatSockets[ClientSocket]] = ClientSocket; // 反向重定向聊天
						byteCount = send(ClientSocket, "Server: Redirected Successfully!", 33, 0);
						if (byteCount == SOCKET_ERROR) {
							iResult = WSAGetLastError();
							cerr << "recv failed with Code: " << iResult << endl;
							if (iResult == 10054)
								cerr << ClientPortTransfer[atoi(ClientInfo.servstr)] << " form port " << ClientInfo.servstr << " exited unexpectly" << endl;
							ClientNameTransfer.erase(UserName);
							ClientPortTransfer.erase(atoi(ClientInfo.servstr));
							if (ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
							{
								send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
								ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
							}
							ChatSockets.erase(ClientSocket);
							LinkToServer.erase(ClientSocket);// 断开连接需要清理旧的映射信息.
							closesocket(ClientSocket);
							return 1;
						}
					}
					else {
						if (strcmp(Buffer, "Server") == 0)
						{
							byteCount = send(ClientSocket, "Server: Redirected to Server!", 30, 0);
							if (byteCount == SOCKET_ERROR) {
								iResult = WSAGetLastError();
								cerr << "recv failed with Code: " << iResult << endl;
								if (iResult == 10054)
									cerr << ClientPortTransfer[atoi(ClientInfo.servstr)] << " form port " << ClientInfo.servstr << " exited unexpectly" << endl;
								ClientNameTransfer.erase(UserName);
								ClientPortTransfer.erase(atoi(ClientInfo.servstr));
								if (ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
								{
									send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
									ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
								}
								ChatSockets.erase(ClientSocket);
								LinkToServer.erase(ClientSocket);// 断开连接需要清理旧的映射信息.
								closesocket(ClientSocket);
								return 1;
							}
							if (ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
							{
								send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
								ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
							}
							ChatSockets[ClientSocket] = CmdResult.ChatSocket;
						}
						else
						{
							byteCount = send(ClientSocket, "Server: No such a user and redirected to Server...", 51, 0);
							if (byteCount == SOCKET_ERROR) {
								iResult = WSAGetLastError();
								cerr << "recv failed with Code: " << iResult << endl;
								if (iResult == 10054)
									cerr << ClientPortTransfer[atoi(ClientInfo.servstr)] << " form port " << ClientInfo.servstr << " exited unexpectly" << endl;
								ClientNameTransfer.erase(UserName);
								ClientPortTransfer.erase(atoi(ClientInfo.servstr));
								if (ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
								{
									send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
									ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
								}
								ChatSockets.erase(ClientSocket);
								LinkToServer.erase(ClientSocket);// 断开连接需要清理旧的映射信息.
								closesocket(ClientSocket);
								return 1;
							}
							if (ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
							{
								send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
								ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
							}
							ChatSockets[ClientSocket] = CmdResult.ChatSocket;
						}
					}
				}
				else if (CmdResult.cmd == "all") { // 查看在线用户
					strcpy_s(Buffer, "Server: ");
					for (map<INT, string>::iterator i = ClientPortTransfer.begin(), j = ClientPortTransfer.end(); i != j; i++) {
						strcat_s(Buffer, i->second.c_str());
						strcat_s(Buffer, " ");
					}
					byteCount = send(ClientSocket, Buffer, (INT)strlen(Buffer) + 1, 0);
					if (byteCount == SOCKET_ERROR) {
						iResult = WSAGetLastError();
						cerr << "send failed with Code: " << iResult << endl;
						if (iResult == 10054)
							cerr << ClientPortTransfer[atoi(ClientInfo.servstr)] << " form port " << ClientInfo.servstr << " exited unexpectly" << endl;
						ClientNameTransfer.erase(UserName);
						ClientPortTransfer.erase(atoi(ClientInfo.servstr));
						if(ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
						{
							send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
							ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
						}
						ChatSockets.erase(ClientSocket);
						LinkToServer.erase(ClientSocket);// 断开连接需要清理旧的映射信息.
						closesocket(ClientSocket);
						return 1;
					}
				}
				continue;
			}
			if (ChatSockets[ClientSocket] != INVALID_SOCKET) {
				if(byteCount < DEFAULT_BUFLEN)
					Buffer[byteCount] = '\0';
				ChatTxt = Buffer;
				if (LinkToServer.find(ChatSockets[ClientSocket]) != LinkToServer.end()) { // 送信前需检查对方是否还在线
					byteCount = send(ChatSockets[ClientSocket], ChatTxt.c_str(), (INT)ChatTxt.length(), 0);
					if (byteCount == SOCKET_ERROR) {
						send(ClientSocket, "send failed and redirected to Server", 37, 0);
						if (byteCount == SOCKET_ERROR) {
							iResult = WSAGetLastError();
							cerr << "recv failed with Code: " << iResult << endl;
							if (iResult == 10054)
								cerr << ClientPortTransfer[atoi(ClientInfo.servstr)] << " form port " << ClientInfo.servstr << " exited unexpectly" << endl;
							ClientNameTransfer.erase(UserName);
							ClientPortTransfer.erase(atoi(ClientInfo.servstr));
							if (ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
							{
								send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
								ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
							}
							ChatSockets.erase(ClientSocket);
							LinkToServer.erase(ClientSocket);// 断开连接需要清理旧的映射信息.
							closesocket(ClientSocket);
							return 1;
						}
						ChatSockets[ClientSocket] = INVALID_SOCKET;
					}
					// 对消息转发不进行检测
				}
				else {
					byteCount = send(ClientSocket, "Your friend has quit! And redirect to Server.", 46, 0);
					if (byteCount == SOCKET_ERROR) {
						iResult = WSAGetLastError();
						cerr << "send failed with Code: " << iResult << endl;
						if (iResult == 10054)
							cerr << ClientPortTransfer[atoi(ClientInfo.servstr)] << " form port " << ClientInfo.servstr << " exited unexpectly" << endl;
						ClientNameTransfer.erase(UserName);
						ClientPortTransfer.erase(atoi(ClientInfo.servstr));
						if (ChatSockets[ChatSockets[ClientSocket]] != INVALID_SOCKET)
						{
							send(ChatSockets[ClientSocket], "Your friend has quit! And redirect to Server.", 46, 0);
							ChatSockets[ChatSockets[ClientSocket]] = INVALID_SOCKET;
						}
						ChatSockets.erase(ClientSocket);
						LinkToServer.erase(ClientSocket);// 断开连接需要清理旧的映射信息.
						closesocket(ClientSocket);
						return 1;
					}
					ChatSockets[ClientSocket] = INVALID_SOCKET;
				}
			}
		}
	}
	return 0;
}

/*
* CmdCheck：检查客户端发来的信息是否是命令
* 参数：客户端发送的文本
*/
DWORD WINAPI CmdCheck(CHAR* Txt) {
	if (Txt && Txt[0] == '<')
		return 1;
	return 0;
}

/*
* CmdCommit：解析客户端发送的命令，并将解析结果返回到ChatThread
* 参数：客户端文本
*/
CmdInfo WINAPI CmdCommit(CHAR* txt) {
	INT txtLen = 0; // 文本长度
	INT argc = 0;   // 参数数量
	string argv[10]; // 参数字符串
	string unit; // 参数单元
	CmdInfo result; // 解析结果
	result.ChatSocket = INVALID_SOCKET;

	// 分析命令文本
	txtLen = (INT)strlen(txt);
	for (INT i = 1; i < txtLen; i++) {
		if (txt[i] == ' ') {
			argv[argc++] = unit;
			unit.clear();
			continue;
		}
		unit.push_back(txt[i]);
	}
	argv[argc++] = unit;

	// 存储命令
	result.cmd = argv[0];
	if (argv[0] == "sendto") {
		sprintf_s(txt, DEFAULT_BUFLEN, argv[1].c_str());
		result.ChatSocket = (ClientNameTransfer.find(argv[1]) != ClientNameTransfer.end() ? ClientNameTransfer[argv[1]] : INVALID_SOCKET);
	}
	else if (argv[0] == "all") {
		result.cmd = argv[0];
	}
	return result;
}
