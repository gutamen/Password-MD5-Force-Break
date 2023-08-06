#include <stdio.h>
#include <stdlib.h>
//#include <openssl/md5.h>
#include <string.h>
#include <omp.h>
#include<unistd.h>
#include <stdint.h>
#include <time.h>
#define MAX 10
#define MD5_DIGEST_LENGTH 16

typedef unsigned char byte;



// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[64] = {
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
 
// r specifies the per-round shift amounts
const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
 
// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
 
void to_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}
 
uint32_t to_int32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0]
        | ((uint32_t) bytes[1] << 8)
        | ((uint32_t) bytes[2] << 16)
        | ((uint32_t) bytes[3] << 24);
}
 
void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {
 
    // These vars will contain the hash
    uint32_t h0, h1, h2, h3;
 
    // Message (to prepare)
    uint8_t *msg = NULL;
 
    size_t new_len, offset;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;
 
    // Initialize variables - simple count in nibbles:
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
 
    //Pre-processing:
    //append "1" bit to message    
    //append "0" bits until message length in bits ≡ 448 (mod 512)
    //append length mod (2^64) to message
 
    for (new_len = initial_len + 1; new_len % (512/8) != 448/8; new_len++)
        ;
 
    msg = (uint8_t*)malloc(new_len + 8);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
    for (offset = initial_len + 1; offset < new_len; offset++)
        msg[offset] = 0; // append "0" bits
 
    // append the len in bits at the end of the buffer.
    to_bytes(initial_len*8, msg + new_len);
    // initial_len>>29 == initial_len*8>>32, but avoids overflow.
    to_bytes(initial_len>>29, msg + new_len + 4);
 
    // Process the message in successive 512-bit chunks:
    //for each 512-bit chunk of message:
    for(offset=0; offset<new_len; offset += (512/8)) {
 
        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        for (i = 0; i < 16; i++)
            w[i] = to_int32(msg + offset + i*4);
 
        // Initialize hash value for this chunk:
        a = h0;
        b = h1;
        c = h2;
        d = h3;
 
        // Main loop:
        for(i = 0; i<64; i++) {
 
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;          
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }
 
            temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;
 
        }
 
        // Add this chunk's hash to result so far:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
 
    }
 
    // cleanup
    free(msg);
 
    //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    to_bytes(h0, digest);
    to_bytes(h1, digest + 4);
    to_bytes(h2, digest + 8);
    to_bytes(h3, digest + 12);
}


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
		
        md5(stringTeste, strlen(stringTeste), hash2);
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
    
    
    #pragma omp parallel shared(parada) private(incrementador, hash2) num_threads(12)
    {
        int trava = 0;
        int vetorBase36[len+1];
        char stringTeste[len+1];
        uint8_t hash3[MD5_DIGEST_LENGTH];  // string hashes
        for(int i = 0; i < len+1; i++){
            vetorBase36[i] = 0;
            stringTeste[i] = 0;
        }

        vetorBase36[0] = 1;
    
    
        
        //printf("Vetor = %d\nThread NUM: %d\n", vetorBase36[0], omp_get_thread_num());
        vetorBase36[0] += omp_get_thread_num();

        while (parada == 0 && trava == 0) {

            //printf("Vetor = %d\n", vetorBase36[0]);

            for (int j = 0; j < len; j++) {
                stringTeste[j] = letters[vetorBase36[j]];
            }

            //printf("Testado: %s\n", stringTeste);
            md5(stringTeste, strlen(stringTeste), hash3);
            
            
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
void strHex_to_uint8_t(char * str, uint8_t  * hash){
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
	uint8_t  hash1[MD5_DIGEST_LENGTH]; // password hash
	uint8_t  hash2[MD5_DIGEST_LENGTH]; // string hashes

	// Input:
	r = scanf("%s", hash1_str);

	// Check input.
	if (r == EOF || r == 0)
	{
		fprintf(stderr, "Error!\n");
		exit(1);
	}
	memset(hash2, 0, MD5_DIGEST_LENGTH);
	
	
	// Convert hexadecimal string to hash byte.
	strHex_to_uint8_t(hash1_str, hash1);
	
	//char teste[4] = "0000";
	
	//md5(teste, 4, hash2);
	
	/*for(int i = 0; i < MD5_DIGEST_LENGTH; i++)
		printf("%x", hash2[i]);
	
	printf("\n");*/

	
	//print_digest(hash1);

	// Generate all possible passwords of different sizes.
	/*for(len = 1; len <= lenMax; len++){
		memset(str, 0, len+1);
    iterate(hash1, hash2, str, 0, len, &ok);
	}*/
	printf("Começo iteração \n");
	clock_t start = clock();
    
	
    iterativeIterateParalel(hash1, hash2, 10);
	//iterativeIterate(hash1, hash2, 10);
	clock_t end = clock();
	double tempo_execucao = (double)(end - start) / CLOCKS_PER_SEC;
	printf("Tempo de execução: %.6f segundos\n", tempo_execucao);
}