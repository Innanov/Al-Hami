#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "api.h"


/**********Key Recovery Attack *************/
int recovery(int c){
    switch(c){
        case 14 : return -2;
        case 15 : return -1;
        case  0 : return  0;
        case  1 : return  1;
        case  2 : return  2;
        case  6 : return -2;
        case  7 : return -1;
        case  8 : return  0;
        case  9 : return  1;
        case 10 : return  2;
    }
}

static void Recovery_Attack(){

    int r = 1;
    /* random init */
    unsigned char       rand_seed[48];
    unsigned char       entropy_input[48];
    //srand(time(NULL));
    srand(r);
    for (int i=0; i<48; i++)
        entropy_input[i] = rand() % 48;
    randombytes_init(entropy_input, NULL, 256);//将命令中的r作为随机数生成器的种子，这意味着密钥生成函数的结果相同


    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES]; //生成要破解的Bob私钥sB

    /* the s recovered by adversary */
    signed char         recs[KYBER_K][KYBER_N] = { 0 };
    /* the polyvec of true s */
    polyvec             skpoly = { { 0 } };    
    /* the randomness recovered by adversary */
    uint8_t m[KYBER_SYMBYTES];

    /* get key pair */
    indcpa_keypair(pk, sk, &skpoly);//修改了密钥生成函数，增加了skpoly参数，以存储生成私钥sk，为了下面的对比


    int B = 213;//B的取值大于等于213，小于等于363

    for(int i = 0; i < KYBER_K; i++) {
        for(int j = 0; j < KYBER_N; j++) {
                polyvec PA = { 0 };  //init PA = 0
                j == 0 ? (PA.vec[i].coeffs[0] = B) 
                       : (PA.vec[i].coeffs[256-j] = (-1)*B);

                uint8_t r[256];
                oracle_recovery(r,PA,sk);
                recs[i][j] = recovery(r[0]);
        }
    }

        /* check the recs recovered by adversary  ==  the true s */

        // for(int i = 0; i < KYBER_K; i++){
        //     for(int j = 0; j < KYBER_N; j++){
        //         printf("%d ", recs[i][j]);
        //     }
        // }
        // printf("\n");
        // for(int i = 0; i < KYBER_K; i++){
        //     for(int j = 0; j < KYBER_N; j++){
        //         printf("%d ", skpoly.vec[i].coeffs[j]);
        //     }
        // }

    int checks = 0;
    for(int i = 0; i < KYBER_K; i++) {
        for(int j = 0; j < KYBER_N; j++) {
            if(recs[i][j] != skpoly.vec[i].coeffs[j]) {
                checks++;
                printf("error s in s[%d][%d] ", i, j);
            }
        }   
    }
    /* print the queries */
    if(checks == 0){
        printf("correct\n");
        for(int i = 0; i < KYBER_K; i++){
            for(int j = 0; j < KYBER_N; j++){
                printf("%d ", recs[i][j]);
            }
            printf("\n");
        }
    }
    else 
        printf("not correct\n");
    return;
}


int main(){
    Recovery_Attack();
    return 1;
}