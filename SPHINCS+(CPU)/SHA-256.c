#include "type.h"
#include "SHA-256.h"
const u32 cont[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void Hash_Block(IN u32* const pt)
{
	u32 W[64], a, b, c, d, e, f, g, h, temp1 = 0, temp2 = 0;
	int i = 0;

	for (i = 0; i < 16; i++)
		W[i] = ENDIAN_CHANGE(pt[i]);


	for (i = 16; i < 64; i++)
		W[i] = W[i - 16] + W[i - 7] + WE0(W[i - 15]) + WE1(W[i - 2]);

	a = state_seed[0];
	b = state_seed[1];
	c = state_seed[2];
	d = state_seed[3];
	e = state_seed[4];
	f = state_seed[5];
	g = state_seed[6];
	h = state_seed[7];

	
	for (i = 0; i < 64; i++)
	{
		temp1 = h + BS1(e) + Ch(e, f, g) + cont[i] + W[i];
		temp2 = (BS0(a)) + (Maj(a, b, c));
		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	state_seed[0] += a;
	state_seed[1] += b;
	state_seed[2] += c;
	state_seed[3] += d;
	state_seed[4] += e;
	state_seed[5] += f;
	state_seed[6] += g;
	state_seed[7] += h;

}


/**
* @brief      중복적으로 사용하는 SEED 값 해시 블록 연산 초기화
* @param      pubkey			공개 키 SEED
* @return     실행 결과
*/
int init_Hash_func(IN u8* pubkey)
{
	u8 BLOCK[HASHBLOCK];
	u32 i = 0;

	for (i = 0; i < DIGEST; i++)
		BLOCK[i] = pubkey[i];
	for (i = DIGEST; i < HASHBLOCK; i++)
		BLOCK[i] = 0;

	//init seed state
	state_seed[0] = 0x6a09e667;
	state_seed[1] = 0xbb67ae85;
	state_seed[2] = 0x3c6ef372;
	state_seed[3] = 0xa54ff53a;
	state_seed[4] = 0x510e527f;
	state_seed[5] = 0x9b05688c;
	state_seed[6] = 0x1f83d9ab;
	state_seed[7] = 0x5be0cd19;
	state_seed[8] = 0;
	
	Hash_Block((u32*)BLOCK);
	state_seed[8] = 0;
	state_seed[9] = 0x00000040;

}