#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include "i_crypto.h"

#define BUF_SIZE 100
#define NAME_SIZE 20

int cipher_id = I_CIPHER_ID_AES128;

//클라이언트의 정보를 담고 있는 구조체
typedef struct ClientSockInfo{
	int sock;
	char name[NAME_SIZE];
	char msg[BUF_SIZE];
	uint8_t key[16];
	int flag;
	I_CIPHER_PARAMETERS param;
} ClientSockInfo;

void* send_msg(ClientSockInfo* arg);
void* recv_msg(ClientSockInfo* arg);
int recv_all(int msg_length, int sock, uint8_t* buf);
int read_all(int msg_length, int sock, uint8_t* buf);
void error_handling(char* message);
void init_ClientSockInfo(ClientSockInfo* client);

int main(int argc, char* argv[]){
	int ret = 0;
	ClientSockInfo client;
	struct sockaddr_in serv_addr;
	pthread_t send_thread, recv_thread;
	void* thread_return;

	uint8_t public_key[] = "-----BEGIN PUBLIC KEY-----\n"\
              "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
              "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
              "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
              "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
              "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
              "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
              "wQIDAQAB\n"\
              "-----END PUBLIC KEY-----\n";
	uint32_t public_keylength = strlen(public_key);

	uint8_t private_key[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
               "MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
               "vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
               "Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
               "yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
               "WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
               "gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
               "omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
               "N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
               "X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
               "gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
               "vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
               "1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
               "m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
               "uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
               "JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
               "4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
               "WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
               "nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
               "PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
               "SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
               "I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
               "ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
               "yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
               "w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
               "uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
               "-----END RSA PRIVATE KEY-----\n";
	uint32_t private_keylength = strlen(private_key);
	
	uint8_t encKey[256];
	uint32_t encKeylength = 0;
	uint32_t keylength = 0;
	int msg_length = 0;

	//init client	
	init_ClientSockInfo(&client);
	client.param.mode = I_CIPHER_MODE_CBC;

	if(argc != 4){//경로/ip/port/name
		printf("Usage : %s <IP> <port> <name> \n", argv[0]);
		exit(EXIT_FAILURE);
	}
	//이름과 소켓을 구조체에 저장장
	sprintf(client.name, "[%s]", argv[3]);
	client.sock = socket(PF_INET, SOCK_STREAM, 0);

	//init server info
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port=htons(atoi(argv[2]));

	//연결
	connect(client.sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

	//연결에 성공하면 서버에 공개키의 길이와 공개키를 보냄
	msg_length = htonl(public_keylength);
	send(client.sock, &msg_length, sizeof(msg_length), 0);
	send(client.sock, public_key, public_keylength, 0);
	
	//자신이 보낸 공개키로 암호화된 대칭키를 서버로부터 획득
	msg_length = 0;
	recv(client.sock, &msg_length, sizeof(msg_length), 0);
	msg_length = ntohl(msg_length);
	encKeylength = recv_all(msg_length, client.sock, encKey);
	if(encKeylength == -1 || encKeylength != msg_length){
		printf("main error, encKeylength : %d, msg_length : %d\n", encKeylength, msg_length);
		close(client.sock);
		return -1;
	}
	hexdump("encKey", encKey, encKeylength);

	//암호화된 대칭키를 자신의 개인키로 복호화하여 최종적으로 대칭키 획득
	recv(client.sock, &keylength, sizeof(keylength), 0);//원본 대칭키의 길이를 받음
	keylength = ntohl(keylength);
	ret = private_decrypt(encKey, encKeylength, private_key, client.key);
	if(ret==-1 || ret != keylength){
		printf("failed dec key\n");
		printf("ret %d, key %d\n", ret, keylength);
		close(client.sock);
		return ret;
	}
	hexdump("key", client.key, 16);

	//쓰레드 생성
	pthread_create(&send_thread, NULL, send_msg, (void*)&client);
	pthread_create(&recv_thread, NULL, recv_msg, (void*)&client);

	pthread_join(send_thread, &thread_return);
	if(client.flag == 1){
		printf("연결을 종료합니다.\n");
		pthread_cancel(recv_thread);
	}
	pthread_join(recv_thread, &thread_return);

	close(client.sock);
	
	return 0;
}

//ClientSockInfo 구조체 초기화
void init_ClientSockInfo(ClientSockInfo* client){
	memset(client, 0, sizeof(ClientSockInfo));
	memset(&(client->param), 0, sizeof(I_CIPHER_PARAMETERS));
	memset(client->param.iv, 0, 16);
	client->param.ivlength = 16;
}

//전송 받을 메시지의 크기를 먼저 받았을 때 그 크기만큼 데이터를 읽는 함수(recv함수가 한번에 모든 데이터를 다 안읽어왔을수도 있기 때문)
int recv_all(int msg_length, int sock, uint8_t* buf){
    int ret = 0;

    // fd_set 구조체 초기화
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    while (ret != msg_length) {
        // select 함수 호출
        int ready = select(sock + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            return -1;
        } else if (ready == 0) {
            // 타임아웃 발생
            return -1;
        } else {
            ret += recv(sock, buf+ret, msg_length-ret, 0);
        }
    }
    return ret;
}
//전송 받을 메시지의 크기를 먼저 받았을 때 그 크기만큼 데이터를 읽는 함수(read함수가 한번에 모든 데이터를 다 안읽어왔을수도 있기 때문)
int read_all(int msg_length, int sock, uint8_t* buf){
    int ret = 0;

    // fd_set 구조체 초기화
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    while (ret != msg_length) {
        // select 함수 호출
        int ready = select(sock + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            return -1;
        } else if (ready == 0) {
            // 타임아웃 발생
            return -1;
        } else {
            ret += read(sock, buf+ret, msg_length-ret);
        }
    }
    return ret;
}

//전체 메시지를 암호화해서 서버에 전송
void* send_msg(ClientSockInfo* client){
	char msg[BUF_SIZE] = {0x00, };
	char name_msg[NAME_SIZE + BUF_SIZE] ={0x00, };//buffer for sending message with name
	AES_KEY encKey;
	//clinet = (CliencSockInfo*)client;
	uint8_t encData[256] = {0x00, };
	uint32_t encDataLength = 0;
	uint32_t msg_length = 0;//메세지를 보내기 전, 메시지 크기를 보내기 위한 변수(htonl()로 빅엔디안으로 크기를 담음)

	//대칭키 생성
	if(AES_set_encrypt_key(client->key, 128, &(encKey)) < 0){
		printf("key 생성 오류\n");
		return 0;
	}

	//처음 연결 성공하면 연결 메시지 보냄
	sprintf(name_msg, "%s %s", client->name, "Connected...\n");
	i_enc(cipher_id, &encKey, &(client->param), name_msg, strlen(name_msg), encData, &encDataLength);
	msg_length = htonl(encDataLength);//보낼 데이터의 크기를 빅엔디안으로 저장
	write(client->sock, &msg_length, sizeof(msg_length));//크기부터 보냄
	write(client->sock, encData, encDataLength);//크기를 보낸 후 메세지를 보냄

	while(1){
		msg_length = 0;
		memset(msg, 0 , BUF_SIZE);
		memset(name_msg, 0, NAME_SIZE+BUF_SIZE);
		memset(encData, 0, 256);
		encDataLength = 0;
		printf("-> ");
		fgets(msg, BUF_SIZE, stdin);
		//q or Q를 입력받으면 클로즈 메시지 보내고 소켓 종료
		if(!strcmp(msg, "q\n") || !strcmp(msg, "Q\n")){
			sprintf(name_msg, "%s %s", client->name, "Closed...\n");
			i_enc(cipher_id, &encKey, &(client->param), name_msg, strlen(name_msg), encData, &encDataLength);
			msg_length = htonl(encDataLength);
			write(client->sock, &msg_length, sizeof(msg_length));
			write(client->sock, encData, encDataLength);
			client->flag = 1;
			break;
		}
		sprintf(name_msg, "%s %s", client->name, msg);
		i_enc(cipher_id, &encKey, &(client->param), name_msg, strlen(name_msg), encData, &encDataLength);
		msg_length = htonl(encDataLength);
		write(client->sock, &msg_length, sizeof(msg_length));
		write(client->sock, encData, encDataLength);
	}
	return NULL;
}
//서버로부터 받은 다른 클라이언트의 메시지를 복호화하여 콘솔에 출력
void* recv_msg(ClientSockInfo* client){
	char name_msg[NAME_SIZE+BUF_SIZE] = {0x00,};
	int msg_length = 0;
	int str_len = 0;
	AES_KEY decKey;
	uint8_t decData[256] = {0x00,};
	uint32_t decDataLength = 0;

	//대칭키 생성
	if(client->param.mode == I_CIPHER_MODE_CTR){//ctr모드이면 encrypt키로 키 설정
		if(AES_set_encrypt_key(client->key, 128, &decKey) < 0){
			printf("decKey 생성 오류\n");
			return 0;
		}
	}
	else{
		if(AES_set_decrypt_key(client->key, 128, &decKey) < 0){
			printf("encKey 생성 오류\n");
			return 0;
		}
	}
	//recv msg...
	while(1){
		read(client->sock, &msg_length, sizeof(msg_length));
		msg_length = ntohl(msg_length);
		str_len = read_all(msg_length, client->sock, name_msg);
		if(str_len == -1 || str_len != msg_length){
			printf("recv_msg()에러 str_len = %d, msg_length = %d\n", str_len, msg_length);
			return (void*)-1;
		}
		i_dec(cipher_id, &decKey, &(client->param), name_msg, str_len, decData, &decDataLength);
		decData[decDataLength] = '\0';
		fputs(decData, stdout);
		memset(name_msg, 0, NAME_SIZE+BUF_SIZE);
		memset(decData, 0, decDataLength);
		decDataLength = 0;
		msg_length = 0;
		str_len = 0;
	}
	return NULL;
}

void error_handling(char* message){
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}
