#pragma once

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
#define HASHBLOCK	(64)
u8 state_seed[40];

//SPHINCS+ section
#define LARER	(17)		//SUBTREE LAYER

//FORS section
#define FORS_PK	(DIGEST)
#define FORS_MSG 