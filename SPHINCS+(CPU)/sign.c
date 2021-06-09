#include "type.h"
#include "SHA-256.h"



/**
* @brief      ���� �� ����
* @param      result			��� ���� �迭
* @param      xLen				��� ����
* @return     ���� ���
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
* @brief	seed�� ���� ���� Ű/���� Ű ����
* @brief	sk : [SK_SEED || SK_PRF || PUB_SEED || root]
* @brief	pk : [PUB_SEED || root]
* @param	pubkey		����Ű ������ �迭	
* @param    prikey		����Ű ������ �迭
* @return   ���� ���
*/
int generate_Key(OUT u8* pubkey, OUT u8* prikey)
{
	u8 SEED[SEED_BYTE];
	randombytes(SEED, SEED_BYTE);

	//������ SEED�� �������� Ű�� �ʱ�ȭ
	memcpy(prikey, SEED, SEED_BYTE);
	memcpy(pubkey, SEED + (2 * DIGEST), DIGEST);

	//�ؽ� �� �ʱ�ȭ(���Ŀ� ����� ���� �̸� �ʱ�ȭ�Ͽ� �ߺ������� ���)
	init_Hash_func(pubkey);

	return SUCCESS;
}

int main() {
	srand(time(NULL));
}