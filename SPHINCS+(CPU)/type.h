#pragma once

//Basic 
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
#define IN
#define OUT


//SPHINCS DEFINE
#define DIGEST 32
#define PK_BYTE	(DIGEST * 2)
#define SK_BYTE (2 * DIGEST + (PK_BYTE))
#define FORS_PK	(DIGEST)
#define FORS_MSG 