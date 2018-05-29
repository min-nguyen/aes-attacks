#include <iostream>
#include <cstdlib>
#include <fstream>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include "omp.h"
#include <vector>
#include <chrono> 
#include <openssl/aes.h> 
#include <ctime>
#include <algorithm>
//-----------------------------#
//-------- Global Defs --------#
//-----------------------------#

#define byte uint8_t
#define SIZE 256
#define ITRS 1

#define KeySize 128
#define CipherSize 
#define byte uint8_t

#define BUFFER_SIZE ( 80 )
#define R 8
#define F 1
#define P 0
#define I 0
#define J 0

using namespace std;

void clean(int x);

int interactions = 0;
int faults = 0;
int N[16];
pid_t pid        = 0;   
byte Mul[256][256];
int   target_raw[ 2 ];  
int   attack_raw[ 2 ];  
FILE* target_out = NULL;
FILE* target_in  = NULL;

// ---- Byte order data required for generating key hypothesis
const byte byte_order1[] = {0, 13, 10,7};
const byte byte_order2[] = {4, 1, 14, 11};
const byte byte_order3[] = {8, 5, 2, 15};
const byte byte_order4[] = {12, 9, 6, 3};

const byte byte_ordered1[] = {0,7,10,13};
const byte byte_ordered2[] = {1,4,11,14};
const byte byte_ordered3[] = {2,5,8,15};
const byte byte_ordered4[] = {3,6,9,12};

const byte byte_index1[] = {0, 3, 2, 1};
const byte byte_index2[] = {1, 0, 3, 2};
const byte byte_index3[] =  {2, 1, 0, 3}; 
const byte byte_index4[] = {3, 2, 1, 0};

const byte delt_order1[] = {1,0,0,2};
const byte delt_order2[] = {0,0,2,1};
const byte delt_order3[] = {0,2,1,0};
const byte delt_order4[] = {2,1,0,0};


byte Sbox[] = {  
         0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
         0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
         0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
         0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
         0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
         0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
         0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
         0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
         0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
         0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
         0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
         0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
         0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
         0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
         0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
         0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
         
byte RSbox[] = {
         0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
         0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
         0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
         0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
         0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
         0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
         0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
         0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
         0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
         0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
         0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
         0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
         0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
         0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
         0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
         0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

byte Rcon[] = {
         0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
         0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
         0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
         0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
         0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
         0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
         0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
         0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
         0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
         0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
         0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
         0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
         0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
         0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
         0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
         0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d};

// Acquire encryption of plaintext m, to acquire either faulted or non faulted cipher
void interact(byte m[16], byte c[16], bool isFault)
{
    interactions++;

    if (isFault){   
        faults++;
        fprintf( target_in, "%d,%d,%d,%d,%d\n",R,F,P,I,J);
    }
    else{
        fprintf( target_in, "\n");
	}

    fflush( target_in );
    for (int i=0;i<16;i++){
        fprintf( target_in, "%02X",m[i]);
	}

    fprintf(target_in,"\n");
    fflush( target_in );
    
    for (int i=0;i<16;i++){
        fscanf( target_out, "%2hhx",&c[i]);
	}
}

inline
byte mul(byte x, byte y)
{
    byte r=0, c;
    for (int i=0;i<8;i++)
    {
        if (y&1)
            r^=x;
        y >>=1;
        c = x&128;
        x <<= 1;
        x &= 255;
        if (c)
            x ^=27;
    }
    return r;
}

//Inverse key for given round
void inv_key_once(byte k[16], int round)
{
    k[15] ^= k[11];
    k[14] ^= k[10];
    k[13] ^=  k[9];
    k[12] ^=  k[8];
    k[11] ^=  k[7];
    k[10] ^=  k[6];
    k[9]  ^=  k[5];
    k[8]  ^=  k[4];
    k[7]  ^=  k[3];
    k[6]  ^=  k[2];
    k[5]  ^=  k[1];
    k[4]  ^=  k[0];
    k[3]  ^= Sbox[k[12]];
    k[2]  ^= Sbox[k[15]];
    k[1]  ^= Sbox[k[14]];
    k[0]  ^= Sbox[k[13]] ^ Rcon[round];
}

//Inverse whole key from tenth round
void inv_key(byte k[16])
{
    for (int round = 10; round>0;round--)
    {
        inv_key_once(k, round);
    }
}

void printHex(byte k[16]) {
    for (int i = 0 ; i < 16 ; i++) {
        if (0 <= k[i] && k[i] <= 15) {
            printf("0%X", k[i]);
        } else {
            printf("%X", k[i]);        
        }
    }
    printf("\n");
}

// Test AES key
bool AES_validate(byte k[16], byte m[16], byte c[16], byte c_test[16], int count)
{
	AES_KEY rk;
    AES_set_encrypt_key( k, 128, &rk );
    AES_encrypt( m, c_test, &rk );  

    if( !memcmp( c_test, c, 16 * sizeof( byte ) ) ) 
    {
		cout<<"\n -- Key Found -- \n";
		cout<<" Key: ";  printHex(k);
		cout<<" Interactions: "<<interactions<<"\n";
		cout<<" Keys Tested: " << count << "\n";
        return true;
    }
	return false;
}

// Generic equation for key hypothesis generation; to account for all 4 equations i.e. all 4 key byte orders
void gen_hypothise_equation(   	byte c[16], 
				                byte c_fault[16], 
				                byte k[16][1024],
				                const byte byte_order[4], 
				                const byte byte_ordered[4],
				                const byte byte_index[4], 
				                const byte delta_order[4])
{
    int n=0;

    byte  delta[3];
    byte  key_bytes[4];
    
    for (delta[0] = 1; delta[0]!=0; delta[0]++)
    {
        delta[1] = Mul[2][delta[0]],
        delta[2] = Mul[3][delta[0]];
        key_bytes[byte_index[0]] = 0;
        do
        {
            if (delta[delta_order[0]] != (RSbox[c[byte_order[0]] ^ key_bytes[byte_index[0]]]^RSbox[ c_fault[byte_order[0]] ^key_bytes[byte_index[0]]  ]  ))
                continue;
            key_bytes[byte_index[1]]= 0;
            do 
            {
                if (delta[delta_order[1]] != (RSbox[c[byte_order[1]]^key_bytes[byte_index[1] ]]^RSbox[ c_fault[byte_order[1]]^key_bytes[byte_index[1]] ] ))
                    continue;

                key_bytes[byte_index[2]]= 0;
                do 
                {
                    if (delta[delta_order[2]] != (RSbox[c[byte_order[2]]^key_bytes[byte_index[2]]] ^ RSbox[ c_fault[byte_order[2]]^key_bytes[byte_index[2]]  ]  ))
                        continue; 
                    key_bytes[byte_index[3]] = 0;
                    do
                    {
                        if (delta[delta_order[3]] == (RSbox[c[byte_order[3]] ^ key_bytes[byte_index[3]]] ^ RSbox[ c_fault[byte_order[3]] ^ key_bytes[byte_index[3]]] ) )
                        {
                            k[byte_ordered[0]][n] =  key_bytes[0];
                            k[byte_ordered[1]][n] =  key_bytes[1];
                            k[byte_ordered[2]][n] =  key_bytes[2];
                            k[byte_ordered[3]][n] =  key_bytes[3];
                            n++;
                        }
                    }while (++key_bytes[byte_index[3]]!=0);
                }while (++key_bytes[byte_index[2]]!=0);
            }while (++key_bytes[byte_index[1]]!=0);
        } while (++key_bytes[byte_index[0]]!=0);
    }
    N[byte_ordered[0]]=N[byte_ordered[1]]=N[byte_ordered[2]]=N[byte_ordered[3]] = n;
}

// Generate key hypothesis
void genKeyHypothesis(byte c[], byte c_fault[], byte hypothesis[16][1024])
{
	printf("\n ---- Stage 1 Starting ---- \n");

	// Using key  bytes:	{0, 13, 10,7}
    gen_hypothise_equation(c, c_fault, hypothesis, byte_order1, byte_ordered1, byte_index1, delt_order1);
	// Using key  bytes:	{4, 1, 14, 11}
    gen_hypothise_equation(c, c_fault, hypothesis, byte_order2, byte_ordered2, byte_index2, delt_order2);
	// Using key  bytes:	{8, 5, 2, 15}
    gen_hypothise_equation(c, c_fault, hypothesis, byte_order3, byte_ordered3, byte_index3, delt_order3);
	// Using key  bytes:	{12, 9, 6, 3}
    gen_hypothise_equation(c, c_fault, hypothesis, byte_order4, byte_ordered4, byte_index4, delt_order4);

	printf("Generated %ld key hypothesis \n", N[0] * N[1] * N[2] * N[3]);
	printf("\n ---- Stage 1 Finished ---- \n");
}

byte equation_1(byte k[], byte kp[], byte c[], byte c_fault[])
{
    return RSbox[ Mul[ RSbox[c[12]^k[12]] ^ kp[12] ][9 ]
				^ Mul[ RSbox[c[9] ^k[9] ] ^ kp[13] ][14]
				^ Mul[ RSbox[c[6] ^k[6] ] ^ kp[14] ][11]
				^ Mul[ RSbox[c[3] ^k[3] ] ^ kp[15] ][13]
				] ^
			RSbox[
				  Mul[ RSbox[c_fault[12]^k[12]] ^ kp[12] ][9 ]
				^ Mul[ RSbox[c_fault[9] ^k[9] ] ^ kp[13] ][14]
				^ Mul[ RSbox[c_fault[6] ^k[6] ] ^ kp[14] ][11]
				^ Mul[ RSbox[c_fault[3] ^k[3] ] ^ kp[15] ][13]
				];
}

byte equation_2(byte k[], byte kp[], byte c[], byte c_fault[])
{
    return RSbox[ Mul[ RSbox[c[8]  ^ k[8]  ]  ^ kp[8]  ][13]
				^ Mul[ RSbox[c[5]  ^ k[5]  ]  ^ kp[9]  ][9 ]
				^ Mul[ RSbox[c[2]  ^ k[2]  ]  ^ kp[10] ][14]
				^ Mul[ RSbox[c[15] ^ k[15] ]  ^ kp[11] ][11]
				] ^ 
			RSbox[
				  Mul[ RSbox[c_fault[8]  ^ k[8]  ]  ^ kp[8]  ][13]
				^ Mul[ RSbox[c_fault[5]  ^ k[5]  ]  ^ kp[9]  ][9 ]
				^ Mul[ RSbox[c_fault[2]  ^ k[2]  ]  ^ kp[10] ][14]
				^ Mul[ RSbox[c_fault[15] ^ k[15] ]  ^ kp[11] ][11]
				];
}

byte equation_3(byte k[], byte kp[], byte c[], byte c_fault[])
{
    return RSbox[ Mul[ RSbox[c[0]  ^ k[0 ] ] ^ kp[0] ][14]
				^ Mul[ RSbox[c[13] ^ k[13] ] ^ kp[1] ][11]
				^ Mul[ RSbox[c[10] ^ k[10] ] ^ kp[2] ][13]
				^ Mul[ RSbox[c[7]  ^ k[7 ] ] ^ kp[3] ][9 ]
				] ^
				RSbox[
				  Mul[ RSbox[c_fault[0]  ^ k[0 ] ] ^ kp[0] ][14]
				^ Mul[ RSbox[c_fault[13] ^ k[13] ] ^ kp[1] ][11]
				^ Mul[ RSbox[c_fault[10] ^ k[10] ] ^ kp[2] ][13]
				^ Mul[ RSbox[c_fault[7]  ^ k[7 ] ] ^ kp[3] ][9 ]
				];
}

byte equation_4(byte k[], byte kp[], byte c[], byte c_fault[])
{
    return RSbox[ Mul[ RSbox[c[4]  ^ k[4]  ]  ^ kp[4] ][11]
				^ Mul[ RSbox[c[1]  ^ k[1]  ]  ^ kp[5] ][13]
				^ Mul[ RSbox[c[14] ^ k[14] ]  ^ kp[6] ][9 ]
				^ Mul[ RSbox[c[11] ^ k[11] ]  ^ kp[7] ][14]
				] ^ 
				RSbox[
				  Mul[ RSbox[c_fault[4]  ^ k[4]  ]  ^ kp[4] ][11]
				^ Mul[ RSbox[c_fault[1]  ^ k[1]  ]  ^ kp[5] ][13]
				^ Mul[ RSbox[c_fault[14] ^ k[14] ]  ^ kp[6] ][9 ]
				^ Mul[ RSbox[c_fault[11] ^ k[11] ]  ^ kp[7] ][14]
				];
    
}


int execAttack(byte hypothesis[16][1024], byte c[], byte c_fault[], byte m[])
{
	cout << "\n ---- Stage 2 Starting ---- \n";   
	int keys_tested = 0;
    #pragma omp parallel for
    for (int ia = 0; ia <= N[0]; ia++) { 
        for (int ib = 0; ib <= N[1]; ib++)
            for (int ic = 0; ic <= N[2]; ic++)
                for (int id = 1; id < N[3]; id++)
                {
					auto start = std::chrono::high_resolution_clock::now();

                    byte f, c_test[16];

                    byte k[] 	= { hypothesis[0][ia],  hypothesis[1][ib],  hypothesis[2][ic],  hypothesis[3][id], 
									hypothesis[4][ib],  hypothesis[5][ic],  hypothesis[6][id],  hypothesis[7][ia], 
									hypothesis[8][ic],  hypothesis[9][id],  hypothesis[10][ia], hypothesis[11][ib],
									hypothesis[12][id], hypothesis[13][ia], hypothesis[14][ib], hypothesis[15][ic]};

                    byte kp[] 	= { hypothesis[0][ia],  hypothesis[1][ib],  hypothesis[2][ic],  hypothesis[3][id], 
									hypothesis[4][ib],  hypothesis[5][ic],  hypothesis[6][id],  hypothesis[7][ia],
									hypothesis[8][ic],  hypothesis[9][id],  hypothesis[10][ia], hypothesis[11][ib],
									hypothesis[12][id], hypothesis[13][ia], hypothesis[14][ib], hypothesis[15][ic]};                
                    
                    inv_key_once(kp,10);

                    	f 			 = equation_1(k,kp,c,c_fault);
                    if (f 			!= equation_2(k,kp,c,c_fault)) continue;
                    if (Mul[f][2]	!= equation_3(k,kp,c,c_fault)) continue;
                    if (Mul[f][3]	!= equation_4(k,kp,c,c_fault)) continue;
                    inv_key(k);

                    keys_tested++;


					// Validate Key
				    printf("Testing key   : "); printHex(k);
					if(AES_validate(k, m, c, c_test, keys_tested)) exit(0);

                	auto end = std::chrono::high_resolution_clock::now();
					std::chrono::duration<double> elapsed = end - start;
					printf("Round Time Elapsed: %fs\n\n", elapsed.count());
                }
    }
}

void attack()
{
    while (true) 
    {
		byte m[16], c[16], c_fault[16];

		//	Initialise multiply table
	    for (int i=0;i<256;i++)
        	for (int j=0;j<256;j++)
            	Mul[i][j] = mul(i,j);

		// Create random plaintext
		for (int i=0;i<16;i++)
		    do 		m[i] = rand()%256;
		    while 	(m[i]==0);    

		// Acquire cipher and fault injected cipher from oracle
		interact(m,c,false);
		interact(m,c_fault,true);
		byte hypothesis[16][1024];

		// Generate key hypothesis
		genKeyHypothesis(c, c_fault, hypothesis);

		// Attack key bytes
		execAttack(hypothesis, c, c_fault, m);
	}
}

int main(int argc, char* argv[]) {
    if (2 != argc) {
        abort();
    }

    signal( SIGINT, &clean );
    if(pipe(target_raw) == -1)
        abort();
    if(pipe(attack_raw) == -1)
        abort();

    
    switch(pid = fork()) { 
        case -1 : 
            abort();
        
        case +0 : {
            close(STDOUT_FILENO);
            if(dup2(attack_raw[1], STDOUT_FILENO) == -1)
                abort();
            close(STDIN_FILENO);
            if(dup2(target_raw[0],  STDIN_FILENO) == -1) 
                abort();
            execl(&(string("./") + argv[1])[0], (const char *) "",(char *) 0);
            break;
        }
        
        default : {
            if((target_out = fdopen(attack_raw[0], "r")) == NULL)
                abort();
            if((target_in = fdopen(target_raw[1], "w")) == NULL) 
                abort();

				auto start = std::chrono::high_resolution_clock::now();
               	attack();
				auto end = std::chrono::high_resolution_clock::now();
				std::chrono::duration<double> elapsed = end - start;

				printf("\n Total Time Elapsed: %fs\n", elapsed.count());
            
        }
     }
    return 0;
}


void clean(int x) {
    fclose(target_in);
    fclose(target_out);
    close(target_raw[0]); 
    close(target_raw[1]); 
    close(attack_raw[0]); 
    close(attack_raw[1]); 
    if( pid > 0 ) 
        kill( pid, SIGKILL );
    exit( 1 ); 
}

