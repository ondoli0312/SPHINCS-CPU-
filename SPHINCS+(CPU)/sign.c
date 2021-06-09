#include "type.h"
#include "SHA-256.h"



/**
* @brief      랜덤 값 생성
* @param      result			출력 저장 배열
* @param      xLen				출력 길이
* @return     실행 결과
*/
int randombytes(OUT u8* result, IN u64 xLen)
{
	for (int i = 0; i < xLen; i++) {
		result[i] = rand() % 0x100;
	}
	return SUCCESS;
}

int generateKey_TreeHash(u8* output, const u8* sk_seed, const u8* pk_seed, 
	u32 leaf_index, u32 idx_offset, u32* tree_addr)
{
	u8 stack[(SUBTREE_H + 1) * DIGEST];
	u8 heights[(1 << SUBTREE_H) + 1];
	u32 offset = 0;
	u32 idx = 0;
	u32 tree_idx = 0;

	for (idx = 0; idx < (u32)(1 << SUBTREE_H); idx++) {

	}


}

/**
* @brief	seed를 통한 공개 키/개인 키 생성
* @brief	sk : [SK_SEED || SK_PRF || PUB_SEED || root]
* @brief	pk : [PUB_SEED || root]
* @param	pubkey		공개키 저장할 배열	
* @param    prikey		개인키 저장할 배열
* @return   실행 결과
*/
int generate_Key(OUT u8* pubkey, OUT u8* prikey)
{
	u8 SEED[SEED_BYTE];
	randombytes(SEED, SEED_BYTE);

	//생성된 SEED를 바탕으로 키를 초기화
	memcpy(prikey, SEED, SEED_BYTE);
	memcpy(pubkey, SEED + (2 * DIGEST), DIGEST);

	//해시 값 초기화(추후에 사용할 값을 미리 초기화하여 중복적으로 사용)
	init_Hash_func(pubkey);

	return SUCCESS;
}

int main() {
	srand(time(NULL));
}