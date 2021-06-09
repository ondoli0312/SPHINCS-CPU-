#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

//Basic 
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
#define IN
#define OUT
#define SUCCESS	1
//SPHINCS DEFINE

//generate key section
#define DIGEST 32
#define PK_BYTE	(DIGEST * 2)
#define SK_BYTE (2 * DIGEST + (PK_BYTE))
#define SEED_BYTE (DIGEST * 3)

//Hash section
u32 state_seed[10];
#define HASHBLOCK	(64)
#define ROTL(x, n)			(((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR(x, n)			(((x) >> (n)) | ((x) << (32 - (n))))
#define ENDIAN_CHANGE(X)	((ROTL((X),  8) & 0x00ff00ff) | (ROTL((X), 24) & 0xff00ff00))
#define Ch(x, y, z)			((x & y) ^ (~(x) & (z)))
#define Maj(x, y, z)		(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sf(x, n)			(x >> n)
#define WE0(x)				(ROTR(x,  7) ^ ROTR(x, 18) ^ Sf(x, 3))
#define WE1(x)				(ROTR(x,  17) ^ ROTR(x, 19) ^ Sf(x, 10))
#define BS0(x)				((ROTR(x,  2)) ^ ROTR(x, 13) ^ ROTR(x,  22))
#define BS1(x)				(ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x,  25))

//SPHINCS+ section
#define LAYER	(17)		//SUBTREE LAYER
#define HYPERTREE_H (68)
#define SUBTREE_H (HYPERTREE_H / LAYER)

//WOTS section
#define WOTS_W 16
#define ADDR_BYTES 32
#define WOTS_LOGW 4
#define WOTS_LEN_1 ((8 * DIGEST)/ (WOTS_LOGW))
#define WOTS_LEN_2 3
#define WOTS_LEN (WOTS_LEN_1 + WOTS_LEN_2)
#define WOTS_BYTE (WOTS_LEN * DIGEST)
#define WOTS_PK_BYTE (WOTS_BYTE)

//FORS section
#define FORS_PK	(DIGEST)
#define FORS_MSG 

//Basic Function
void set_type(u32 addr[8], u32 type);
void set_keypair_addr(u32 addr[8], u32 keypair);
void copy_subtree_addr(u32 out[8], const u32 in[8]);
void copy_keypair_addr(u32 out[8], const u32 in[8]);
void set_chain_addr(u32 addr[8], u32 chain);