/*
* SOCKET CHATROOM CLIENT
* Copyright ©GUOBAJUN 2022
* USE TCP/IPv4
*/

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <wincrypt.h>

#include <iostream>
#include <cstring>
#include <ctime>
#include <cctype>

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#pragma warning(disable: 4996)

#define SERVER_PORT "10086"
#define DEFAULT_SERVER "127.0.0.1"
#define DEFAULT_BUFLEN 4096
#define UserNameLen 512
#define DEFAULT_HASHLEN 70
#define DEFAULT_RSA_KETLEN 2048
#define DEFAULT_SHA256_CHARLEN 64
#define DEFAULT_AES_KEYLEN 128
#define DEFAULT_AES_BLOCK 16
#define DEFAULT_DH_KEYLEN 512
#define ALICE_MAGICNUM "2F08E400A3"

using std::cin;
using std::cout;
using std::cerr;
using std::endl;
using std::string;

CHAR UserName[UserNameLen];
CHAR PeerName[UserNameLen];
HANDLE hChatThread[2]; // Reserver线程, Sender线程
BOOL EncryptMode = FALSE;

// Universal
VOID Bin2Hex(BYTE* Buffer, CHAR* msg,INT Len)
{
	string result;
	CHAR buf[3]="";
	for (INT i = 0; i < Len; i++) {
		sprintf_s(buf, "%02x", Buffer[i]);
		result += buf;
	}
	strcpy(msg, result.c_str());
}

VOID print2Hex(BYTE* Buffer, INT Len) {
	CHAR buf[3] = "";
	for (INT i = 0; i < Len; i++) {
		sprintf(buf, "%02x", Buffer[i]);
		cout << buf << " ";
	}
	cout << endl;
}

BYTE Hex2Dec(CHAR* hex)
{
	BYTE res = 0;
	if (isdigit(hex[0])) res += (hex[0] - '0') * 16;
	else res += (hex[0] - 'a' + 10) * 16;
	if (isdigit(hex[1])) res += (hex[1] - '0');
	else res += (hex[1] - 'a' + 10);
	return res;
}

VOID Hex2Bin(CHAR* Buffer, BYTE* msg, INT* Len) {
	INT HexLen = lstrlenA(Buffer), cnt = 0;
	CHAR buf[3]= "";
	*Len = HexLen / 2;
	for (INT i = 0; i < HexLen; i += 2) {
		buf[0] = Buffer[i];
		buf[1] = Buffer[i + 1];
		msg[cnt++] = Hex2Dec(buf);
	}
	msg[cnt] = '\0';
}

// SHA256
string SHA256(CHAR* Buffer) {
	string txt = Buffer, Result;
	CHAR buf[3];
	BYTE Hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX context;
	SHA256_Init(&context);
	SHA256_Update(&context, txt.c_str(), txt.size());
	SHA256_Final(Hash, &context);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf_s(buf, "%02x", Hash[i]);
		Result += buf;
	}
	return Result;
}

//AES128
BYTE AESKey[128]; //实际上128位就几个字符
INT AESKeyLen;
AES_KEY KeyE, KeyD;
DWORD WINAPI AESInit()
{
	INT iResult;
	iResult = AES_set_encrypt_key(AESKey, DEFAULT_AES_KEYLEN, &KeyE);
	if (iResult != 0) {
		cerr << "AES_set_encrypt_key failed with Code: " << iResult << endl;
		return 1;
	}
	iResult = AES_set_decrypt_key(AESKey, DEFAULT_AES_KEYLEN, &KeyD);
	if (iResult != 0) {
		cerr << "AES_set_decrypt_key failed with Code: " << iResult << endl;
		return 1;
	}
	return 0;
}

DWORD AES_ECB_Encrypt_ZeroPadding(BYTE* in, BYTE* out, INT inLen)
{
	INT Len = inLen / 16 + 1;
	CHAR* data = (CHAR*)malloc(DEFAULT_AES_BLOCK * Len);
	BYTE* Cipher = (BYTE*)malloc(DEFAULT_AES_BLOCK * Len + 33);
	BYTE* Plain = (BYTE*)malloc(DEFAULT_AES_BLOCK * Len);
	if (!data || !Cipher || !Plain) {
		cerr << "malloc failed..." << endl;
		return 1;
	}
	ZeroMemory(data, DEFAULT_AES_BLOCK * Len);
	ZeroMemory(Cipher, DEFAULT_AES_BLOCK * Len + 33);
	ZeroMemory(Plain, DEFAULT_AES_BLOCK * Len);
	strcpy_s(data, DEFAULT_AES_BLOCK * Len, (const CHAR*)in);
	for (INT i = 0; i < Len; i++)
		AES_ecb_encrypt((BYTE*)(data + i * DEFAULT_AES_BLOCK), Cipher + i * DEFAULT_AES_BLOCK, &KeyE, AES_ENCRYPT);
	memcpy_s(out, 4096, Cipher, DEFAULT_AES_BLOCK * Len + 33);
	free(data);
	free(Cipher);
	free(Plain);
	return 0;
}

DWORD AES_EBC_Decrypt_ZeroPadding(const BYTE* in , BYTE* out, INT inLen)
{
	auto Pres = new CHAR[inLen];
	ZeroMemory(Pres, inLen);
	for (INT i = 0; i < inLen / 16; i++)
		AES_ecb_encrypt((BYTE*)(in + i * DEFAULT_AES_BLOCK), (BYTE*)(Pres + i * DEFAULT_AES_BLOCK), &KeyD, AES_DECRYPT);
	memcpy(out, Pres, inLen);
	delete[] Pres;
	return 0;
}

// DH
static const CHAR DH_P[] = "EBFB36DDEED6B166F8A2022ECCA3B64872E842FA4966A0B22A70188882E7894A1A08A9B3618DCF05CE61B973FC1977ED631953A51624273475AC4F8F3C7BF71D";
static const BYTE DH_G[] = { 2 };
DH* dh = NULL;
BIGNUM* dhP, * dhG;
CHAR myPub[DEFAULT_BUFLEN], peerPub[DEFAULT_BUFLEN];
DWORD WINAPI DH_gen_key()
{
	dh = DH_new();
	if (dhP == NULL)
	{
		dhP = BN_new();
		BN_hex2bn(&dhP, DH_P);
	}
	if (dhG == NULL)
		dhG = BN_bin2bn(DH_G, sizeof(DH_G), NULL);
	if (dhP == NULL || dhG == NULL) {
		cerr << "BN_bin2bn failed..." << endl;
		DH_free(dh);
		dh = NULL;
		return 1;
	}
	DH_set0_pqg(dh, dhP, NULL, dhG);
	if (strcmp(UserName, "Alice") == 0) { // Alice使用爱丽丝魔数
		BIGNUM* Pri = BN_new();
		BN_hex2bn(&Pri, ALICE_MAGICNUM);
		DH_set0_key(dh, NULL, Pri);
	}
	if (DH_generate_key(dh) != 1) {
		cerr << "DH_generate_key failed..." << endl;
		return 1;
	}
	strcpy_s(myPub, BN_bn2hex(DH_get0_pub_key(dh)));
	return 0;
}

DWORD WINAPI DH_calc_shared_key(CHAR* peerHex)
{
	BIGNUM* peerKey;
	peerKey = BN_new();
	BN_hex2bn(&peerKey, peerHex);
	AESKeyLen = DH_compute_key_padded(AESKey, peerKey, dh);
	if (AESKeyLen == -1) {
		cerr << "DH_compute_key_padded failed..." << endl;
		return 1;
	}
	// 截断DH共享密钥为128位
	AESKeyLen = 16;
	AESKey[AESKeyLen] = '\0';
	return 0;
}


// RSA2
RSA *rsa;
CHAR* PrivateKey; // 我的RSA私钥
CHAR* PublicKey;  // 我的RSA公钥
INT PriKeyLen;
INT PubKeyLen;
CHAR RSAChatKey[DEFAULT_RSA_KETLEN];    // 对方的RSA公钥
VOID RSAinit() {
	rsa = RSA_generate_key(DEFAULT_RSA_KETLEN, RSA_3, NULL, NULL); // 生成密钥对

	BIO* Pri = BIO_new(BIO_s_mem());
	BIO* Pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(Pri, rsa, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(Pub, rsa);

	PriKeyLen = BIO_pending(Pri);
	PubKeyLen = BIO_pending(Pub); // 获取密钥长度

	PrivateKey = (CHAR*)malloc(PriKeyLen + 1);
	if (PrivateKey == NULL) {
		cerr << "malloc failed for PrivateKey..." << endl;
		return;
	}
	PublicKey = (CHAR*)malloc(PubKeyLen + 1);
	if (PublicKey == NULL) {
		cerr << "malloc failed for PublicKey..." << endl;
		return;
	}

	BIO_read(Pri, PrivateKey, PriKeyLen);
	BIO_read(Pub, PublicKey, PubKeyLen);

	PrivateKey[PriKeyLen] = '\0';
	PublicKey[PubKeyLen] = '\0';

	RSA_free(rsa);
	BIO_free_all(Pub);
	BIO_free_all(Pri);
}

// RSA私钥签名
string RSA_PriKey_Sign(CHAR* Buffer) {
	CHAR* EncryptedText;
	string EncryptedStr;
	INT iResult;
	BIO* KeyBIO = BIO_new_mem_buf(PrivateKey, PriKeyLen);
	if (!KeyBIO) {
		cerr << "RSA_PriKey_Sign failed..." << endl;
		return string("");
	}
	RSA* rsa = RSA_new();
	rsa = PEM_read_bio_RSAPrivateKey(KeyBIO, NULL, NULL, NULL);
	if (!rsa) {
		BIO_free_all(KeyBIO);
		cerr << "RSA_PriKey_Sign failed..." << endl;
		return string("");
	}

	INT Len = RSA_size(rsa);
	EncryptedText = (CHAR*)malloc(Len * 2 + 1);
	if (EncryptedText == NULL) {
		cerr << "malloc for EncryptedText failed..." << endl;
		return string("");
	}
	ZeroMemory(EncryptedText, (Len * 2 + 1));

	iResult = RSA_private_encrypt(lstrlenA(Buffer), (const BYTE*)Buffer, (BYTE*)EncryptedText, rsa, RSA_PKCS1_PADDING);
	if (iResult >= 0) // 将计算结果保存为HEX串
	{
		Bin2Hex((BYTE*)EncryptedText, EncryptedText, iResult);
		EncryptedStr = string(EncryptedText, iResult * 2); // Bin2Hex长度翻倍
	}
	free(EncryptedText);
	BIO_free_all(KeyBIO);
	RSA_free(rsa);
	return EncryptedStr;
}

// RSA公钥验签
string RSA_PubKey_Verify(CHAR* Buffer, INT mLen) {
	CHAR* DecryptedText;
	string ClearText;
	BIO* KeyBIO = BIO_new(BIO_s_mem());
	BIO_puts(KeyBIO, RSAChatKey);
	if (!KeyBIO) {
		cerr << "RSA_PubKey_Verify failed..." << endl;
		return string("");
	}
	RSA* rsa = RSA_new();
	rsa = PEM_read_bio_RSAPublicKey(KeyBIO, NULL, NULL, NULL);
	if (!rsa) {
		cerr << "RSA_PubKey_Verify failed..." << endl;
		BIO_free_all(KeyBIO);
		RSA_free(rsa);
		return string("");
	}
	INT Len = RSA_size(rsa);
	DecryptedText = (CHAR*)malloc(Len * 2 + 1);
	if (DecryptedText == NULL) {
		cerr << "malloc for EncryptedText failed..." << endl;
		return string("");
	}
	ZeroMemory(DecryptedText, Len * 2 + 1);

	INT iResult = RSA_public_decrypt(mLen, (const BYTE*)Buffer, (BYTE*)DecryptedText, rsa, RSA_PKCS1_PADDING);
	if (iResult >= 0)
		ClearText = string(DecryptedText, iResult);
	free(DecryptedText);
	BIO_free_all(KeyBIO);
	RSA_free(rsa);
	return ClearText;
}

// 密钥交换
DWORD WINAPI KeyConsult(LPVOID lpParam) {
	SOCKET* ServerSocket = (SOCKET*)lpParam;
	string sendBuf;
	INT byteCount;
	sendBuf.clear();
	sendBuf.append("Diffie-Hellman ");
	sendBuf.append(myPub);
	sendBuf.append(" RSA-Pub ");
	sendBuf.append(PublicKey);
	byteCount = send(*ServerSocket, sendBuf.c_str(), (INT)sendBuf.length() + 1, 0); //发送自己的公钥
	while (RSAChatKey[0] == '\0' || peerPub[0] == '\0');// 等待接收公钥
	// cout << peerPub << endl;
	// cout << RSAChatKey << endl;
	DH_calc_shared_key(peerPub);	// 计算AES128密钥
	AESInit();						// 初始化AES加密模块
	cout << "System: Your Message will be encrypted." << endl;
	ExitThread(0);
}

// 综合信息加密
VOID WINAPI MessageEncrypt(CHAR* Buffer,CHAR*oLen, CHAR* mLen)
{
	INT Len = lstrlenA(Buffer); // 原始信息长度
	CHAR Hash[DEFAULT_HASHLEN] = "";
	CHAR msg[DEFAULT_BUFLEN] = "";
	string SignedHash;
	itoa(Len, oLen, 10);                    // 原始信息长度转换为字符串
	strcpy_s(Hash, SHA256(Buffer).c_str()); // 计算消息SHA256 -> SHA256已经是HEX格式
	SignedHash = RSA_PriKey_Sign(Hash);		// 对SHA256值签名并以Hex格式存储
	strcpy_s(msg, SignedHash.c_str());		// SHA256签名作为消息头，添加到msg中
	strcat_s(msg, Buffer);					// 为消息添加签名后的SHA256首部
	AES_ECB_Encrypt_ZeroPadding((BYTE*)msg, (BYTE*)Buffer, Len + (INT)SignedHash.size());// AES加密，结果存储在Buffer中
	Bin2Hex((BYTE*)Buffer, Buffer, ((Len + (INT)SignedHash.length()) / 16 + 1) * 16);// 将密文转换为HEX格式
	Len = lstrlenA(Buffer);
	itoa(Len, mLen, 10); // 加密后密文长度
}

// 综合信息解密
VOID WINAPI MesssageDecrypt(CHAR* Buffer,INT oLen, INT mLen)
{
	CHAR msg[DEFAULT_BUFLEN] = "";
	string verHash;
	INT i, Len, bufLen = 0, msgLen;
	string vResult;
	Hex2Bin(Buffer, (BYTE*)Buffer, &mLen); // 将密文转换为BIN格式 长度折半，所以可以用Buffer自己存
	AES_EBC_Decrypt_ZeroPadding((BYTE*)Buffer, (BYTE*)msg, mLen);// AES解密，结果存储在msg中
	Len = lstrlenA(msg);
	for (i = Len - oLen; i < Len; i++) {// 提取原始消息
		Buffer[bufLen++] = msg[i];
	}
	Buffer[bufLen] = '\0';      // 截断为原始信息 -> 返回到Receiver
	msgLen = Len - oLen;
	msg[msgLen] = '\0';    // 截断为签名后的SHA256
	verHash = SHA256(Buffer);               // 计算收信摘要
	Hex2Bin(msg, (BYTE*)msg, &msgLen);//RSA 从HEX转为BIN 长度减半
	vResult = RSA_PubKey_Verify(msg, msgLen); // 验证签名 获得SHA256
	if (vResult != verHash) {
		cerr << "Warning: The Message you've received may be modified..." << endl;
	}
}

// 清除加密凭证
VOID WINAPI CleanEncrypt()
{
	ZeroMemory(RSAChatKey, DEFAULT_RSA_KETLEN);		// 清除保存的RSA公钥
	ZeroMemory(peerPub, DEFAULT_BUFLEN);			// 清除保存的DH公钥
	ZeroMemory(AESKey, DEFAULT_AES_KEYLEN);
	AESKeyLen = 0;									// 清除协商的AES密钥
	EncryptMode = FALSE;							// 退出加密模式
}






/*
* CmdCheck：检查输入是否为客户端命令
* 参数：客户端输入的文本
* >exit 断开与服务器的连接并关闭客户端
*/
DWORD WINAPI CmdCheck(CHAR* txt) {
	if (txt[0] != '<' && txt[0] != '>')
		return 0;

	INT txtLen = 0;
	INT argc = 0;
	string argv[10];
	string unit;

	txtLen = lstrlenA(txt);
	for (int i = 0; i < txtLen; i++) {
		if (txt[i] == ' ') {
			if (!unit.empty())
				argv[argc++] = unit;
			unit.clear();
			continue;
		}
		unit.push_back(txt[i]);
		if (argc > 8) return 0;
	}
	argv[argc++] = unit;
	if (argv[0] == ">exit") return 1;
	else if (argv[0] == "<sendto") { 
		return 2; 
	}
	else return 0;
}

/*
* msgCheck: 检查收信是否为加密请求
* 参数：来自服务器转发的消息
* Server: [%s] connected with You!
* Your friend has quit! And redirect to Server.
* send failed and redirected to Server
* return 0 无特殊含义
* return 1 进入加密
* return 2 退出加密
* return 3 接下来回收信保密信息
* return 4 收到了公钥
*/
DWORD WINAPI msgCheck(CHAR* txt) {
	INT txtLen = 0;
	INT argc = 0;
	string argv[15];
	string unit;

	txtLen = lstrlenA(txt);
	for (int i = 0; i < txtLen; i++) {
		if (argc > 10) return 0;
		if (txt[i] == ' ') {
			argv[argc++] = unit;
			unit.clear();
			continue;
		}
		unit.push_back(txt[i]);
	}
	argv[argc++] = unit;
	if (argc == 5 && argv[2] == "connected" && argv[1] != UserName)
	{
		strcpy_s(PeerName, argv[1].c_str());
		return 1;
	}
	if (argc == 8 && argv[1] == "friend")
	{
		ZeroMemory(PeerName, UserNameLen);
		return 2;
	}
	if (argc == 6 && argv[3] == "redirected")
	{
		ZeroMemory(PeerName, UserNameLen);
		return 2;
	}
	if (argc == 4 && argv[0] == "oLen" && argv[2] == "mLen") return 3; 
	if (argc == 10 && argv[0] == "Diffie-Hellman") {
		strcpy_s(peerPub, argv[1].c_str());
		strcpy_s(RSAChatKey, txt + 152);
		return 4;
	}
	return 0;
}

DWORD sendtoCheck(CHAR* Buffer) {
	INT Len = lstrlenA(Buffer);
	string unit;
	string argv[10];
	INT argc = 0;
	for (INT i = 0; i < Len; i++) {
		if (Buffer[i] == ' ') {
			if (!unit.empty()) 
				argv[argc++] = unit;
			if (argc > 4)
				break;
			unit.clear();
			continue;
		}
		unit.push_back(Buffer[i]);
	}
	argv[argc++] = unit;
	if (argc != 2) return -1;
	if (argv[1] == PeerName) return 2;
	if (argv[1] == "Server" || argv[1] == UserName) return 1;
	strcpy_s(PeerName, argv[1].c_str());
	return 0;
}

DWORD GetHint(CHAR* txt, INT* oLen, INT* mLen) {
	INT txtLen = 0;
	INT argc = 0;
	string argv[10];
	string unit;

	txtLen = lstrlenA(txt);
	for (int i = 0; i < txtLen; i++) {
		if (argc > 8) return 0;
		if (txt[i] == ' ') {
			if(!unit.empty())
				argv[argc++] = unit;
			unit.clear();
			continue;
		}
		unit.push_back(txt[i]);
	}
	argv[argc++] = unit;
	*oLen = atoi(argv[1].c_str());
	*mLen = atoi(argv[3].c_str()); // 从先行报文中获取 原始信息长度oLen和加密后信息长度mLen
	return 0;
}

/*
* Receiver：接收信息线程所调用的函数
* 参数：服务器Socket
* 会以收到信息的本地时间打上时间戳
*/
DWORD WINAPI Receiver(LPVOID lpParam) {
	SOCKET *ServerSocket = (SOCKET*)lpParam; // 服务器Socket
	CHAR Buffer[DEFAULT_BUFLEN], strNow[DEFAULT_BUFLEN]; // 接收缓存、时间戳
	INT byteCount, iResult, mLen, oLen;
	time_t Now;
	struct tm ptm;
	while (*ServerSocket != INVALID_SOCKET) {
		ZeroMemory(Buffer, DEFAULT_BUFLEN);
		byteCount = recv(*ServerSocket, Buffer, DEFAULT_BUFLEN, 0);
		if (byteCount == SOCKET_ERROR) {
			cerr << "recv failed with Code: " << WSAGetLastError() << endl;
			closesocket(*ServerSocket);
			*ServerSocket = INVALID_SOCKET;
			return 1;
		}
		else if (byteCount == 0) {
			cout << "Connection ended!" << endl;
			*ServerSocket = INVALID_SOCKET;
			break;
		}
		iResult = msgCheck(Buffer);
		if(iResult == 0) {  // 常规信息
			time(&Now);
			localtime_s(&ptm, &Now);
			strftime(strNow, DEFAULT_BUFLEN, "[%x %X] ", &ptm);
			if (byteCount < DEFAULT_BUFLEN)
				Buffer[byteCount] = '\0';
			cout << strNow << Buffer << endl;
		}
		else if (iResult == 1) { // 进入加密模式
			time(&Now);
			localtime_s(&ptm, &Now);
			strftime(strNow, DEFAULT_BUFLEN, "[%x %X] ", &ptm);
			if(byteCount < DEFAULT_BUFLEN)
				Buffer[byteCount] = '\0';
			cout << strNow << Buffer << endl; // 输出服务器的明文通告
			HANDLE hConsult;
			hConsult = CreateThread(NULL, 0, KeyConsult, (LPVOID)ServerSocket, 0, NULL);
			if (hConsult == NULL) {
				cerr << "CreateHandle for hConsult failed..." << endl;
				continue;
			}
			CloseHandle(hConsult);
			EncryptMode = TRUE;
		}
		else if (iResult == 2) { // 明文模式（与服务器直接连接）
			cout << Buffer << endl;
			CleanEncrypt();
		}
		else if (iResult == 3) {
			GetHint(Buffer, &oLen, &mLen); // 经过处理后Buffer已经变为原始信息长度
			byteCount = recv(*ServerSocket, Buffer, DEFAULT_BUFLEN, 0); // 接收加密信息
			if (mLen != byteCount)
				cout << "mLen != ByteCount, please Check" << endl;
			MesssageDecrypt(Buffer,oLen, mLen);
			time(&Now);
			localtime_s(&ptm, &Now);
			strftime(strNow, DEFAULT_BUFLEN, "[%x %X] ", &ptm);
			cout << strNow << PeerName << ": " << Buffer << endl;
		}
	}
	return 0;
}

/*
* Sender：发送信息进程所调用的函数
* 参数：服务器Socket
* 发送非客户端命令的文本（包括对服务器的命令）
*/
DWORD WINAPI Sender(LPVOID lpParam) {
	SOCKET* ServerSocket = (SOCKET*)lpParam; // 服务器Socket
	CHAR Buffer[DEFAULT_BUFLEN]; // 发送缓存
	CHAR mLen[128] = "", oLen[128] = ""; // 送信长度(十进制数字)
	string hint;
	INT byteCount, iResult;
	while (*ServerSocket != INVALID_SOCKET) {
		ZeroMemory(Buffer, DEFAULT_BUFLEN);
		cin.getline(Buffer, DEFAULT_BUFLEN); // 一次读取一行
		iResult = CmdCheck(Buffer);
		if (iResult == 1) { // 关闭客户端
			CleanEncrypt(); // 销毁加密凭证
			shutdown(*ServerSocket, SD_SEND);
			*ServerSocket = INVALID_SOCKET;
			break;
		}
		else if (iResult == 2) { // 聊天对象重定向 + 清除已有密钥 + 进入加密聊天
			CleanEncrypt(); 
			iResult = sendtoCheck(Buffer);
			if (iResult == 1) { // 重定向到Server || Self ， 无需加密
				strcpy(PeerName, Buffer + 8);
				byteCount = send(*ServerSocket, Buffer, lstrlenA(Buffer) + 1, 0);
				if (byteCount == SOCKET_ERROR) {
					cerr << "send failed with Code: " << WSAGetLastError() << endl;
					*ServerSocket = INVALID_SOCKET;
					return 1;
				}
				continue;
			}
			else if (iResult == 2) { //重复重定向
				cout << "You've connected with " << PeerName << endl;
				continue;
			}
			else if(iResult == 0) { // 重定向到有效peer
				byteCount = send(*ServerSocket, Buffer, lstrlenA(Buffer) + 1, 0);
				if (byteCount == SOCKET_ERROR) {
					cerr << "send failed with Code: " << WSAGetLastError() << endl;
					*ServerSocket = INVALID_SOCKET;
					return 1;
				}
				HANDLE hConsult;
				hConsult = CreateThread(NULL, 0, KeyConsult, (LPVOID)ServerSocket, 0, NULL);
				if (hConsult == NULL) {
					cerr << "CreateHandle for hConsult failed..." << endl;
					continue;
				}
				CloseHandle(hConsult);
				EncryptMode = TRUE; // 进入加密聊天模式
				continue;
			}
		}
		if (EncryptMode) {
			MessageEncrypt(Buffer, oLen, mLen);                     // 加密原始信息，并返回原始信息长度
			hint.clear();
			hint.append("oLen ");
			hint.append(oLen);
			hint.append(" mLen ");
			hint.append(mLen);// 给予Peer一个Hint
			send(*ServerSocket, hint.c_str(), (INT)hint.length(), 0);    // 加密模式下明文传输原始信息长度
		}
		if (EncryptMode)
			byteCount = send(*ServerSocket, Buffer, atoi(mLen), 0);
		else
			byteCount = send(*ServerSocket, Buffer, lstrlenA(Buffer) + 1, 0);
		if (byteCount == SOCKET_ERROR) {
			cerr << "send failed with Code: " << WSAGetLastError() << endl;
			*ServerSocket = INVALID_SOCKET;
			return 1;
		}
	}
	return 0;
}

int main(int argc, CHAR **argv) {
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	addrinfo* results = NULL, * ptr = NULL, hints;
	CHAR Buffer[DEFAULT_BUFLEN], hoststr[NI_MAXHOST], servstr[NI_MAXSERV], Server[NI_MAXHOST];
	int iResult;

	// 配置客户端参数
	switch (argc) {
	case 1:
		cout << "Server: ";
		cin >> Server;
		cout << "UserName: ";
		cin >> UserName;
		iResult = getchar(); // 过滤换行符
		break;
	case 2:
		strcpy_s(Server, argv[1]);
		cout << "UserName: ";
		cin >> UserName;
		iResult = getchar();
		break;
	case 3:
		strcpy_s(Server, argv[1]);
		strcpy_s(UserName, argv[2]);
		break;
	default:
		cerr << "Usage: " << argv[0] << " [ServerIP] [UserName]" << endl;
		return 1;
	}

	system("cls");
	cout << "Client initing..." << endl;

	// 初始化WSADATA
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		cout << "WSAStartup failed with Code: " << iResult << endl;
		WSACleanup();
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	
	
	iResult = getaddrinfo(Server, SERVER_PORT, &hints, &results);
	if (iResult != 0) {
		cout << "getaddrinfo failed with Code: " << iResult << endl;
		WSACleanup();
		return 1;
	}
	if (results == NULL) {
		cout << "Server " << argv[1] << " could not be resolved!" << endl;
		WSACleanup();
		return 1;
	}

	// 生成本地密钥
	RSAinit(); // 生成本客户端的RSA密钥
	DH_gen_key(); // 生成本客户端的DH密钥

	// cout << myPub <<'\n' << endl;
	
	cout << "Client up!!!" << endl;

	// 连接到服务器
	ptr = results;
	while (ptr) {
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol); // 创建服务器Socket
		if (ConnectSocket == INVALID_SOCKET) {
			cout << "socket failed with Code: " << WSAGetLastError() << endl;
			WSACleanup();
			return 1;
		}
		iResult = getnameinfo(ptr->ai_addr, (socklen_t)ptr->ai_addrlen, hoststr, NI_MAXHOST, servstr, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
		if (iResult != 0) {
			cout << "getnameinfo failed with Code: " << iResult << endl;
			WSACleanup();
			return 1;
		}
		cout << "Client attempting connection to " << hoststr << " port " << servstr << endl;

		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen); // 连接到服务器
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			ptr = ptr->ai_next;
		}
		else {
			break;
		}
	}

	freeaddrinfo(results); // 连接后可释放results
	results = NULL;

	if (ConnectSocket == INVALID_SOCKET) {
		cout << "connect failed with Code: " << WSAGetLastError() << endl;
		WSACleanup();
		return 1;
	}
	else {
		cout << "Successfully connected to Server!" << endl;
	}


	// 发送试探信息
	sprintf_s(Buffer, UserName);
	iResult = send(ConnectSocket, Buffer, lstrlenA(Buffer) + 1, 0);
	if (iResult == SOCKET_ERROR) {
		cout << "send failed with Code: " << WSAGetLastError() << endl;
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}
	iResult = recv(ConnectSocket, Buffer, DEFAULT_BUFLEN, 0);
	if (iResult == SOCKET_ERROR) {
		cout << "recv failed with Code: " << WSAGetLastError() << endl;
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}
	if (iResult == 0) {
		cout << "Server closed connection" << endl;
		return 0;
	}

	cout << "\nHello " << UserName << ". Client is ready now!!!\n" << endl;

	// 建立收信线程
	hChatThread[0] = CreateThread(NULL, 0, Receiver, &ConnectSocket, 0, NULL);
	if (hChatThread[0] == NULL) {
		cerr << "CreateThread for Receiver failed with Code: " << GetLastError() << endl;
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}
	//建立送信线程
	hChatThread[1] = CreateThread(NULL, 0, Sender, &ConnectSocket, 0, NULL);
	if (hChatThread[1] == NULL) {
		cerr << "CreateThread for Sender failed with Code: " << GetLastError() << endl;
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}
	
	iResult = WaitForMultipleObjects(2, hChatThread, TRUE, INFINITE); // 等待所有线程结束，设置超时时间为无线
																	  // 注意是INT的INFINITE而不是float的INFINITY
	if ((iResult == WAIT_FAILED) || (iResult == WAIT_TIMEOUT)) {
		cerr << "WaitForMultipleObjects failed with Code: " << GetLastError() << endl;
		WSACleanup();
		return 1;
	}

	closesocket(ConnectSocket);
	WSACleanup();
	return 0;
}
