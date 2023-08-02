#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <string.h>
#include <omp.h>
#include<unistd.h>

#define MAX 10

typedef unsigned char byte;

char letters[] = "\0ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

/*
 * Print a digest of MD5 hash.
*/
void print_digest(byte * hash){
	int x;

	for(x = 0; x < MD5_DIGEST_LENGTH; x++)
        	printf("%02x", hash[x]);
	printf("\n");
}

/*
 * This procedure generate all combinations of possible letters
*/
void iterate(byte * hash1, byte * hash2, char *str, int idx, int len, int *ok) {
	int c;

	// 'ok' determines when the algorithm matches.
	if(*ok) return;
	if (idx < (len - 1)) {
		// Iterate for all letter combination.
		for (c = 0; c < strlen(letters) && *ok==0; ++c) {
			str[idx] = letters[c];
			// Recursive call
			iterate(hash1, hash2, str, idx + 1, len, ok);
		}
	} else {
		// Include all last letters and compare the hashes.
		for (c = 0; c < strlen(letters) && *ok==0; ++c) {
			str[idx] = letters[c];
			MD5((byte *) str, strlen(str), hash2);
            printf("digeriu %s\n", str);
			if(strncmp((char*)hash1, (char*)hash2, MD5_DIGEST_LENGTH) == 0){
				printf("found: %s\n", str);
				print_digest(hash2);
				*ok = 1;
			}
		}
	}
}

void iterativeIterate(byte* hash1, byte* hash2, int len) {
    int parada = 0;
    int vetorBase36[len+1];
    char stringTeste[len+1];
    
    for(int i = 0; i < len+1; i++){
        vetorBase36[i] = 0;
        stringTeste[i] = 0;
    }

    vetorBase36[0] = 1;
    
    for(;parada == 0;){
        
        for(int j = 0; len > j; j++){
            stringTeste[j] = letters[vetorBase36[j]];
        }
        //printf("Testado: %s\n", stringTeste);
        MD5((byte *) stringTeste, strlen(stringTeste), hash2);
        if(strncmp((char*)hash1, (char*)hash2, MD5_DIGEST_LENGTH) == 0){
			printf("found: %s\n", stringTeste);
			print_digest(hash2);
			parada++;
		}
        
        vetorBase36[0]++;
        int incrementador = 0;
        while (vetorBase36[incrementador] >= 37 ) {
            vetorBase36[incrementador] = 1;
            incrementador++;

            if(incrementador >= len){
                printf("Tamanho limite Atingido\nCom esse tamanho de string não se encontrou resposta\n");
                return;
            }
            vetorBase36[incrementador]++;

        }


    }


}


void iterativeIterateParalel(byte* hash1, byte* hash2, int len) {
    int parada = 0;
    

    int incrementador = 0;
    
    
    #pragma omp parallel shared(parada) private(incrementador, hash2) num_threads(4)
    {
        int trava = 0;
        int vetorBase36[len+1];
        char stringTeste[len+1];
        byte hash3[MD5_DIGEST_LENGTH];  // string hashes
        for(int i = 0; i < len+1; i++){
            vetorBase36[i] = 0;
            stringTeste[i] = 0;
        }

        vetorBase36[0] = 1;
    
    
        
        printf("Vetor = %d\nThread NUM: %d\n", vetorBase36[0], omp_get_thread_num());
        vetorBase36[0] += omp_get_thread_num();

        while (parada == 0 && trava == 0) {

            //printf("Vetor = %d\n", vetorBase36[0]);

            for (int j = 0; j < len; j++) {
                stringTeste[j] = letters[vetorBase36[j]];
            }

            //printf("Testado: %s\n", stringTeste);
            MD5((byte*)stringTeste, strlen(stringTeste), hash3);
            
            
            if (strncmp((char*)hash1, (char*)hash3, MD5_DIGEST_LENGTH) == 0) {
                printf("found: %s\n", stringTeste);
                print_digest(hash3);
                parada++;
            }
            
            vetorBase36[0]+= omp_get_num_threads();
            //printf("%s %d %d\n", stringTeste, vetorBase36[0], omp_get_thread_num());
            //sleep(1);
           
            if(vetorBase36[0] >= 37){
                vetorBase36[0] = omp_get_thread_num() + 1;
                incrementador = 1;
                vetorBase36[incrementador]++;

                while (vetorBase36[incrementador] >= 37 ) {
                    vetorBase36[incrementador] = 1;
                    incrementador++;

                    if(incrementador >= len){
                        printf("Tamanho limite Atingido\nCom esse tamanho de string não se encontrou resposta\n");
                        trava++;
                    }
                    vetorBase36[incrementador]++;

                }


            }
        
        }
    }
}
//Nessa versão iterativa, foi utilizada uma pilha (stack) para controlar as iterações e os backtracks necessários para gerar todas as combinações de letras. A pilha é implementada como um vetor de inteiros e seu tamanho é dinamicamente alocado para ter o mesmo tamanho da string str.





/*
 * Convert hexadecimal string to hash byte.
*/
void strHex_to_byte(char * str, byte * hash){
	char * pos = str;
	int i;

	for (i = 0; i < MD5_DIGEST_LENGTH/sizeof *hash; i++) {
		sscanf(pos, "%2hhx", &hash[i]);
		pos += 2;
	}
}

int main(int argc, char **argv) {
	char str[MAX+1];
	int lenMax = MAX;
	int len;
	int ok = 0, r;
	char hash1_str[2*MD5_DIGEST_LENGTH+1];
	byte hash1[MD5_DIGEST_LENGTH]; // password hash
	byte hash2[MD5_DIGEST_LENGTH]; // string hashes

	// Input:
	r = scanf("%s", hash1_str);

	// Check input.
	if (r == EOF || r == 0)
	{
		fprintf(stderr, "Error!\n");
		exit(1);
	}

	// Convert hexadecimal string to hash byte.
	strHex_to_byte(hash1_str, hash1);

	memset(hash2, 0, MD5_DIGEST_LENGTH);
	//print_digest(hash1);

	// Generate all possible passwords of different sizes.
	/*for(len = 1; len <= lenMax; len++){
		memset(str, 0, len+1);
    iterate(hash1, hash2, str, 0, len, &ok);
	}*/

    iterativeIterateParalel(hash1, hash2, 10);
}
