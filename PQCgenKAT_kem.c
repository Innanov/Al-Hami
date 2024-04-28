
//
//  PQCgenKAT_kem.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "api.h"

#define	MAX_MARKER_LEN		50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

/********** Attack *************/

/* the table showing h and corresponding s
 * example  h = 5 corresponding s = 0   */
static int htable[5][2] = {{5, 0}, {6, 1}, {4, -1}, {7, 2}, {3, -2}};
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
/* check h to get corresponding s */ 
static int checkh(int h) {
    for(int i = 0; i < 5; i++) {
        if(htable[i][0] == h)
            return htable[i][1];
    }
    return 99;      //fail check
}

static int kyber_Attack(int r) {


    /* random init */
    unsigned char       rand_seed[48];
    unsigned char       entropy_input[48];
    //srand(time(NULL));
    srand(r);
    for (int i=0; i<48; i++)
        entropy_input[i] = rand() % 48;
    randombytes_init(entropy_input, NULL, 256);//将命令中的r作为随机数生成器的种子，这意味着密钥生成函数的结果相同


    /*pk sk ct*/
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES];

    /* the s  recovered by adversary */
    signed char         recs[KYBER_K][KYBER_N] = { 0 };
    /* the polyvec of true s */
    polyvec             skpoly = { { 0 } };
    /* the m set by adversary */
    unsigned char       m[KYBER_SYMBYTES]  = { 0 };
    m[0] = 0x1; // first coeff of m is 1

    /* get key pair */
    if (  crypto_kem_keypair(pk, sk, &skpoly) != 0 ) {//修改了密钥生成函数，增加了skpoly参数，以存储生成私钥sk，为了下面的对比
        printf("crypto_kem_keypair error\n");
        return KAT_CRYPTO_FAILURE;
    }

    
    int h ;   //parameter
    int query = 0;

/*  controlling the version of the attack , */
#define OPTIMIZATION        // uncomment this to get the version without optimization
#ifndef OPTIMIZATION        //未优化的版本，h遍历0到16
    /*  no optimization */
    /* loop h to recover s */
    for(int i = 0; i < KYBER_K; i++) {
        for(int k = 0; k < KYBER_N; k++) {
            for(h = 0; h < 16; h++) {
                kemenc_Attack(ct, m, pk, h, k, i); // choose appropriate ct
                query += 1;                        // count queries  
                if(oracle(ct, sk, m) == 1) {       // send ct to oracle 
                    //printf("%d ",h);
                    break;
                }
            }
            recs[i][k] = checkh(h);                // check the value of h to get s
        }
    }


#else
    /*  optimization */            //优化的版本
    for(int i = 0; i < KYBER_K; i++) {
        for(int k = 0; k < KYBER_N; k++) {

            kemenc_Attack(ct, m, pk, 5, k, i);       // set h = 5
            // int num = 0;
            // for (int m = 0;m<CRYPTO_CIPHERTEXTBYTES;m++){
            //     if (ct[m] == 0)
            //         num+=1;
            //     if (ct[m] == 5)
            //         num=0;
            //     printf("%d ",ct[m]);
            // }
            // printf("num:%d ",num);
            // char outstr2[1024] = {0};
	        // base64_encode(ct,strlen(ct),outstr2,1024);
            // printf("%d\n",strlen(ct));
            // printf("ct:%s\n",outstr2);
            // char outstr1[1024] = {0};
            // printf("%d\n",strlen(sk));
	        // base64_encode(sk,strlen(sk),outstr1,1024);
            // printf("sk:%s\n",outstr1);

            if(oracle(ct, sk, m) == 1) {
                query += 1;
                kemenc_Attack(ct, m, pk, 4, k, i);  // set h = 4
                // char outstr2[1024] = {0};
                // base64_encode(ct,strlen(ct),outstr2,1024);
                // printf("%d\n",strlen(ct));
                // printf("ct:%s\n",outstr2);
                if(oracle(ct, sk, m) == 0) {
                    recs[i][k] = 0;
                    query += 1;
                }
                else {
                    query += 1;
                    kemenc_Attack(ct, m, pk, 3, k, i);
                // char outstr2[1024] = {0};
                // base64_encode(ct,strlen(ct),outstr2,1024);
                // printf("%d\n",strlen(ct));
                // printf("ct:%s\n",outstr2);
                    if(oracle(ct, sk, m) == 0) {
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
                kemenc_Attack(ct, m, pk, 6, k, i);
                if(oracle(ct, sk, m) == 1) {
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
#endif
    /* check the recs recovered by adversary  ==  the true s */
    int checks = 0;
    for(int i = 0; i < KYBER_K; i++) {
        for(int j = 0; j < KYBER_N; j++) {
            if(recs[i][j] != skpoly.vec[i].coeffs[j]) {
                checks++;
                printf("error s in s[%d][%d] ", i, j);
            }
        }   
        // if(checks == 0){
        //     printf("right s[%d]\n", i);
        // }
    }
    /* print the queries */
    if(checks == 0){
        printf("fact queries: %d\n", query);
        for(int i = 0; i < KYBER_K; i++){
            for(int j = 0; j < KYBER_N; j++){
                printf("%d ", recs[i][j]);
            }
            printf("\n");
        }
    }
    else 
        printf("not correct\n");
    return query;
}


// need a rand seed from shell
int
main(int argc, char * argv[])
{

    if(argc == 1) {
        printf("need a number for random\n");
        return 0;
    }
    int rand = atoi(argv[1]);

    kyber_Attack(rand);     
    return 0;
   
}



