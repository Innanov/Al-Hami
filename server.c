#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "rng.h"
#include "api.h"
#include <time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include "indcpa.h"

#define PORT 8080
#define	MAX_MARKER_LEN		50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

static const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int base64_encode(const unsigned char *src, size_t src_len, char *dst, size_t dst_len) {
    size_t i, j;
    unsigned char buf[3];
    int k;
    char tmp[4];

    for (i = 0, j = 0; i < src_len; i += 3) {
        buf[0] = src[i];
        buf[1] = (i+1 < src_len) ? src[i+1] : 0;
        buf[2] = (i+2 < src_len) ? src[i+2] : 0;

        tmp[0] = base64_chars[buf[0] >> 2];
        tmp[1] = base64_chars[((buf[0] & 0x03) << 4) | (buf[1] >> 4)];
        tmp[2] = base64_chars[((buf[1] & 0x0F) << 2) | (buf[2] >> 6)];
        tmp[3] = base64_chars[buf[2] & 0x3F];

        if (j + 4 <= dst_len) {
            dst[j++] = tmp[0];
            dst[j++] = tmp[1];
            dst[j++] = tmp[2];
            dst[j++] = tmp[3];
        } else {
            return 0;
        }
    }

    k = src_len % 3;
    if (k > 0) {
        dst[j-1] = '=';
        if (k == 1) {
            dst[j-2] = '=';
        }
    }

    return j;
}

void add_prefix(int num, char *str) {
    char prefix[3]; // 存储前缀的字符数组
    sprintf(prefix, "%d:", num); // 将整数转换为字符串

    int len = strlen(str); // 获取原始字符串的长度

    // 将字符串向后移动 prefix 的长度个字节
    memmove(str + strlen(prefix), str, len + 1);

    // 将前缀复制到字符串的前面
    memcpy(str, prefix, strlen(prefix));
}

int get_prefix(const char *str) {
    char prefix[16]; // 存储前缀的字符数组
    int i;

    // 找到第一个冒号的位置
    for (i = 0; i < strlen(str); i++) {
        if (str[i] == ':') {
            break;
        }
    }

    // 如果找不到冒号，则返回0
    if (i == strlen(str)) {
        return 0;
    }

    // 将冒号前面的部分复制到前缀字符数组中
    memcpy(prefix, str, i);
    prefix[i] = '\0';

    // 将前缀字符串转换为整数并返回
    return atoi(prefix);
}

// 将消息填充到指定长度
void pad_message(char *message, int len) {
    int message_len = strlen(message);
    if (message_len >= len) {
        return; // 消息已经达到或超过指定长度，无需填充
    }
    memset(message + message_len, 0x00, len - message_len); // 用0x00填充到指定长度
}

// 从消息中移除填充
void unpad_message(char *message, int len) {
    int i;
    for (i = len - 1; i >= 0; i--) {
        if (message[i] != 0x00) {
            break; // 找到最后一个不是填充的字符
        }
    }
    message[i + 1] = '\0'; // 将最后一个不是填充的字符后面的内容去除
}

int receive_message(int sock, char *buffer, int bufsize) {
    int total_bytes_received = 0;
    int bytes_received = 0;
    int expected_bytes = bufsize;

    while (total_bytes_received < expected_bytes) {
        bytes_received = recv(sock, buffer + total_bytes_received, expected_bytes - total_bytes_received, 0);

        if (bytes_received <= 0) {
            return -1;
        }

        total_bytes_received += bytes_received;
    }

    return total_bytes_received;
}

char* remove_prefix(char* message) {
    char* result;
    char* colon_index;

    colon_index = strchr(message, ':');
    if (colon_index != NULL) {
        result = colon_index + 1;
    } else {
        result = message;
    }
    return result;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char *hello = "Hello from server";
    char buffer[2048] = {0};
    int valread, opcode;

    // 创建socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // 设置socket选项
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // 设置socket地址
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 绑定socket到地址
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // 监听socket
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    // 接收连接请求
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
        perror("accept failed");
        exit(EXIT_FAILURE);
    }

    // 发送数据到客户端
    //send(new_socket, hello, strlen(hello), 0);
    //printf("Hello message sent\n");

        //产生密钥
        /* random init */
    unsigned char       rand_seed[48];
    unsigned char       entropy_input[48];
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int r = 1;
    srand(r);
    for (int i=0; i<48; i++)
    entropy_input[i] = rand() % 48;
    randombytes_init(entropy_input, NULL, 256);//将命令中的r作为随机数生成器的种子，这意味着密钥生成函数的结果相同
    
    polyvec             skpoly = { { 0 } };
    if (  crypto_kem_keypair(pk, sk, &skpoly) != 0 ) {//修改了密钥生成函数，增加了skpoly参数，以存储生成私钥sk，为了下面的对比
        printf("crypto_kem_keypair error\n");
        return KAT_CRYPTO_FAILURE;
        }
   
    while(1){

        memset(buffer, 0, 2048);
        //valread = read(new_socket, buffer, 1024);
        valread = receive_message(new_socket, buffer, 2048);
        unpad_message(buffer,2048);
        unsigned char *message = buffer;
        opcode = get_prefix(message);
        message = remove_prefix(message);
    
        if (opcode == 1){
            //将公钥发送给客户端
            add_prefix(2,pk);
            pad_message(pk,2048);
            send(new_socket, pk, 2048,0);
        }
        if (opcode == 3){
            
            // char outstr2[1024] = {0};
	        // base64_encode(message,strlen(message),outstr2,1024);
            // printf("%d\n",strlen(message));
            // printf("ct:%s\n",outstr2);
            // char outstr3[1024] = {0};
            // printf("%d\n",strlen(sk));
	        // base64_encode(sk,strlen(sk),outstr3,1024);
            // printf("sk:%s\n",outstr3);
            //收到client的Pb，c1，c2，计算出自己的对称密钥KA
            unsigned char       ct[CRYPTO_CIPHERTEXTBYTES];

            // int num = 0;
            // for (int m = 0;m<CRYPTO_CIPHERTEXTBYTES;m++){
            //     if (message[m] == 0)
            //         num+=1;
            //     if (message[m] == 5)
            //         num=0;
            //     printf("%d ",message[m]);
            // }
            // printf("num:%d ",num);
            memcpy(ct,message,CRYPTO_CIPHERTEXTBYTES);
            // for (int m = 0;m<CRYPTO_CIPHERTEXTBYTES;m++)
            // printf("%d ",ct[m]);

            unsigned char m_dec[KYBER_SYMBYTES] = { 0 };
            indcpa_dec(m_dec, ct, sk);    //decrypt the ct

            // printf("%d\n",strlen(m_dec));
            // char outstr1[1024] = {0};
	        // base64_encode(m_dec,strlen(m_dec),outstr1,1024);
            // printf("m_dec:%s\n",outstr1);
            // printf("m_dec:");
            // for(int i=0;i<32;i++) {
            // printf("%02x", m_dec[i]); // 打印哈希结果
            // }
            // printf("\n");
            unsigned char K_A[32];
            SHA256(m_dec, 32, K_A); // 进行哈希计算
            // printf("K_A:");
            // for(int i=0;i<32;i++) {
            // printf("%02x", K_A[i]); // 打印哈希结果
            // }
             // 使用生成的密钥加密 "hello" 
            unsigned char plaintext[] = "hello";
            unsigned char iv[] = "1234567890123456"; // 初始化向量
            unsigned char ciphertext[1024] = {0}; // 存放密文
            EVP_CIPHER_CTX *ctx;
            int len, ciphertext_len;

            ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, K_A, iv);
            EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen(plaintext));
            ciphertext_len = len;
            EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
            ciphertext_len += len;
            EVP_CIPHER_CTX_free(ctx);

            // printf("Ciphertext: ");
            // for(int i=0; i<ciphertext_len; i++) {
            // printf("%02x", ciphertext[i]);
            // }
            // printf("\n");

            //发送一条加密的“hello”消息，操作码：4
            unsigned char mess[2048] = {0};
            memcpy(mess,ciphertext,ciphertext_len);

            char prefix[3]; // 存储前缀的字符数组
            sprintf(prefix, "%d:", 4); // 将整数转换为字符串            
            //add_prefix(4,ciphertext);
            //send(sock, hello, strlen(hello), 0);
            memmove(mess + strlen(prefix), mess, ciphertext_len + 1);
            memcpy(mess, prefix, strlen(prefix));
            send(new_socket, mess, 2048,0);
        }
        if (opcode == 0){
        //     for(int i = 0; i < KYBER_K; i++){
        //     for(int j = 0; j < KYBER_N; j++){
        //         printf("%d ", skpoly.vec[i].coeffs[j]);
        //     }
        //     printf("\n");
        // }
            break;
        }

    }


    return 0;
}
