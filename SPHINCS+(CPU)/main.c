#include "type.h"
int main() {
	u8 pk[64];
	u8 sk[128];
	generate_Key(pk, sk);
	for (int i = 0; i < 64; i++) {
		printf("%02X ", pk[i]);
	}
	printf("\n");
}