#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "rng.h"
#include "api.h"
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#define PORT 8080

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

int attack(int sock, int k, int i, int h){
    //申请交换密钥
    char kei[] = "Key Exchange Init";
    char buffer[2048] = {0};
    add_prefix(1,kei);
    pad_message(kei,2048);
    send(sock, kei, 2048,0);

    int valread;
    unsigned char       m[KYBER_SYMBYTES]  = { 0 };
    m[0] = 0x1; // first coeff of m is 1

    int opcode;

    while(1){
        memset(buffer, 0, 2048);
        valread = receive_message(sock, buffer, 2048);
        unpad_message(buffer,2048);
        unsigned char *message = buffer;
        opcode = get_prefix(message);
        message = remove_prefix(message);
        if (opcode == 2){
            unsigned char       pk[CRYPTO_PUBLICKEYBYTES];
            memcpy(pk,message,CRYPTO_PUBLICKEYBYTES);
            // char outstr1[1024] = {0};
	        // base64_encode(pk,strlen(pk),outstr1,1024);
            // printf("pk:%s\n",outstr1);
            unsigned char       ct[CRYPTO_CIPHERTEXTBYTES];
            kemenc_Attack(ct, m, pk, h, k, i);       // set h = 5
            // char outstr1[1024] = {0};
	        // base64_encode(ct,strlen(ct),outstr1,1024);
            // printf("ct:%s\n",outstr1);
            // for (int m = 0;m<CRYPTO_CIPHERTEXTBYTES;m++)
            // printf("%d ",ct[m]);
            
            unsigned char mess[2048] = {0};
            memcpy(mess,ct,CRYPTO_CIPHERTEXTBYTES);

            // int num = 0;
            // for (int m = 0;m<CRYPTO_CIPHERTEXTBYTES;m++){
            //     if (mess[m] == 0)
            //         num+=1;
            //     if (mess[m] == 5)
            //         num=0;
            //     printf("%d ",mess[m]);
            // 
            // printf("num:%d ",num);
            //add_prefix(3,mess);//这也是错的
            char prefix[3]; // 存储前缀的字符数组
            sprintf(prefix, "%d:", 3); // 将整数转换为字符串
            // 将字符串向后移动 prefix 的长度个字节
            memmove(mess + strlen(prefix), mess, CRYPTO_CIPHERTEXTBYTES + 1);

            // 将前缀复制到字符串的前面
            memcpy(mess, prefix, strlen(prefix));
            send(sock, mess, 2048,0);
        }
        if (opcode == 4){

            // printf("m:");
            // for(int i=0;i<32;i++) {
            // printf("%02x", m[i]); // 打印哈希结果
            // }
            // printf("\n");
            unsigned char K_B[32];
            SHA256(m, 32, K_B); // 进行哈希计算
            // printf("K_B:");
            // for(int i=0;i<32;i++) {
            // printf("%02x", K_B[i]); // 打印哈希结果
            // }
            // 使用生成的密钥加密 "hello"
            unsigned char plaintext[] = "hello";
            unsigned char iv[] = "1234567890123456"; // 初始化向量
            unsigned char ciphertext[1024] = {0}; // 存放密文
            EVP_CIPHER_CTX *ctx;
            int len, ciphertext_len;

            ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, K_B, iv);
            EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen(plaintext));
            ciphertext_len = len;
            EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
            ciphertext_len += len;
            EVP_CIPHER_CTX_free(ctx);
            
            // printf("message: ");
            // for(int i=0; i<ciphertext_len; i++) {
            // printf("%02x", message[i]);
            // }
            // printf("\n");


            // printf("Ciphertext: ");
            // for(int i=0; i<ciphertext_len; i++) {
            // printf("%02x", ciphertext[i]);
            // }
            // printf("\n");
            // char outstr1[1024] = {0};
	        // base64_encode(m,strlen(m),outstr1,1024);
            // printf("m:%s\n",outstr1);

            // char outstr1[1024] = {0};
	        // base64_encode(K_B,strlen(K_B),outstr1,1024);
            // printf("K_B:%s\n",outstr1);

            int oracle = 1;
            for(int j=0;j<ciphertext_len;j++){
                if (ciphertext[j] != message[j])
                {//printf("%02x %02x||", ciphertext[j],message[j]);
                    oracle = 0;}
            }
            //printf("oracle:%d\n",oracle);
            return oracle;
        }
    }

}

int main(int argc, char const *argv[]) {
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char *hello = "Hello from client";
    char kei[] = "Key Exchange Init";
    char buffer[2048] = {0};

    // 创建socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    // 设置socket地址
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // 将IP地址从点分十进制转换为网络字节序的二进制形式
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    // 连接服务端
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

        /* the s  recovered by adversary */
    signed char         recs[KYBER_K][KYBER_N] = { 0 };

        /* the m set by adversary */
    unsigned char       m[KYBER_SYMBYTES]  = { 0 };
    m[0] = 0x1; // first coeff of m is 1

    int h ;   //parameter
    int query = 0;


    for(int i = 0; i < KYBER_K; i++) {
        for(int k = 0; k < KYBER_N; k++) {
            int oracle = attack(sock,k,i,5);
            if(oracle == 1) {
                query += 1;
                int oracle = attack(sock,k,i,4);
                if(oracle == 0) {
                    recs[i][k] = 0;
                    query += 1;
                }
                else {
                    query += 1;
                    int oracle = attack(sock,k,i,3);
                    if(oracle == 0) {
                        recs[i][k] = -1;
                        query += 1;
                    }
                    else {
                        recs[i][k] = -2;
                        query += 1;
                    }   
                }
            }
            else {
                query += 1;
                int oracle = attack(sock,k,i,6);
                if(oracle == 1) {
                    recs[i][k] = 1;
                    query += 1;
                }
                else {
                    recs[i][k] = 2;
                    query += 1; 
                }
            }
        }
    }

    //     /* check the recs recovered by adversary  ==  the true s */
    // int checks = 0;
    // for(int i = 0; i < KYBER_K; i++) {
    //     for(int j = 0; j < KYBER_N; j++) {
    //         if(recs[i][j] != skpoly.vec[i].coeffs[j]) {
    //             checks++;
    //             printf("error s in s[%d][%d] ", i, j);
    //         }
    //     }   
    //     // if(checks == 0){
    //     //     printf("right s[%d]\n", i);
    //     // }
    // }
    // /* print the queries */
    // if(checks == 0){
    //     printf("fact queries: %d\n", query);
    //     for(int i = 0; i < KYBER_K; i++){
    //         for(int j = 0; j < KYBER_N; j++){
    //             printf("%d ", recs[i][j]);
    //         }
    //         printf("\n");
    //     }
    // }
    // else 
    //     printf("not correct\n");
    // return query;

    printf("fact queries: %d\n", query);
    for(int i = 0; i < KYBER_K; i++){
    for(int j = 0; j < KYBER_N; j++){
        printf("%d ", recs[i][j]);
    }
    printf("\n");
    }
    return 0;
}
