/* 
 * "Small Hello World" example. 
 * 
 * This example prints 'Hello from Nios II' to the STDOUT stream. It runs on
 * the Nios II 'standard', 'full_featured', 'fast', and 'low_cost' example 
 * designs. It requires a STDOUT  device in your system's hardware. 
 *
 * The purpose of this example is to demonstrate the smallest possible Hello 
 * World application, using the Nios II HAL library.  The memory footprint
 * of this hosted application is ~332 bytes by default using the standard 
 * reference design.  For a more fully featured Hello World application
 * example, see the example titled "Hello World".
 *
 * The memory footprint of this example has been reduced by making the
 * following changes to the normal "Hello World" example.
 * Check in the Nios II Software Developers Manual for a more complete 
 * description.
 * 
 * In the SW Application project (small_hello_world):
 *
 *  - In the C/C++ Build page
 * 
 *    - Set the Optimization Level to -Os
 * 
 * In System Library project (small_hello_world_syslib):
 *  - In the C/C++ Build page
 * 
 *    - Set the Optimization Level to -Os
 * 
 *    - Define the preprocessor option ALT_NO_INSTRUCTION_EMULATION 
 *      This removes software exception handling, which means that you cannot 
 *      run code compiled for Nios II cpu with a hardware multiplier on a core 
 *      without a the multiply unit. Check the Nios II Software Developers 
 *      Manual for more details.
 *
 *  - In the System Library page:
 *    - Set Periodic system timer and Timestamp timer to none
 *      This prevents the automatic inclusion of the timer driver.
 *
 *    - Set Max file descriptors to 4
 *      This reduces the size of the file handle pool.
 *
 *    - Check Main function does not exit
 *    - Uncheck Clean exit (flush buffers)
 *      This removes the unneeded call to exit when main returns, since it
 *      won't.
 *
 *    - Check Don't use C++
 *      This builds without the C++ support code.
 *
 *    - Check Small C library
 *      This uses a reduced functionality C library, which lacks  
 *      support for buffering, file IO, floating point and getch(), etc. 
 *      Check the Nios II Software Developers Manual for a complete list.
 *
 *    - Check Reduced device drivers
 *      This uses reduced functionality drivers if they're available. For the
 *      standard design this means you get polled UART and JTAG UART drivers,
 *      no support for the LCD driver and you lose the ability to program 
 *      CFI compliant flash devices.
 *
 *    - Check Access device drivers directly
 *      This bypasses the device file system to access device drivers directly.
 *      This eliminates the space required for the device file system services.
 *      It also provides a HAL version of libc services that access the drivers
 *      directly, further reducing space. Only a limited number of libc
 *      functions are available in this configuration.
 *
 *    - Use ALT versions of stdio routines:
 *
 *           Function                  Description
 *        ===============  =====================================
 *        alt_printf       Only supports %s, %x, and %c ( < 1 Kbyte)
 *        alt_putstr       Smaller overhead than puts with direct drivers
 *                         Note this function doesn't add a newline.
 *        alt_putchar      Smaller overhead than putchar with direct drivers
 *        alt_getchar      Smaller overhead than getchar with direct drivers
 *
 */

#include "system.h"
#include "sys/alt_stdio.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SHA1_BLOCK_SIZE 64
#define SHA1_HASH_SIZE 20
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

static size_t pre_process_length;

#define MAX_MESSAGE_LENGTH (256+64)

void sha_1(uint32_t *hash_ptr, const uint8_t *message,
		const uint32_t *prev_hash);
void print_hex_and_binary(const uint8_t *data, size_t length);
void sha1_preprocess(const char *message, uint8_t *processed_message,
		size_t *length);
void print_blocks(const uint8_t *data, size_t length);

typedef unsigned int alt_u32;

#define __I volatile const // read-only permission
#define __IO volatile // read/write permission ...
#define __O volatile // write only permission ;-) doesn't work in C...

typedef struct {
	__IO alt_u32 DATA_REG;
	__IO alt_u32 DIRECTION_REG;
	__IO alt_u32 INTERRUPTMASK_REG;
	__IO alt_u32 EDGECAPTURE_REG;
	__O alt_u32 OUTSET_REG;
	__O alt_u32 OUTCLEAR_REG;
} PIO_TYPE;

#define LEDS (*((PIO_TYPE *) 0x80011030 ))

volatile unsigned long delay = 0;

int main(void) {
	LEDS.DATA_REG = 0x00;
	alt_putstr("FSOC platform alive!");

	const char a[] = "FSOC23/24 is fun!";
	const char *input_string = a;

	// Initial hash values
	uint32_t initial_hash[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
			0xC3D2E1F0 };
	uint32_t expected_hash[5] = { 0xa617f4b3, 0xa108b6dd, 0x82bb8c4a,
			0x16ab0b35, 0x2a32a0b9 };
	uint32_t hash_result[5];

	uint8_t processed_message[MAX_MESSAGE_LENGTH];
	size_t processed_length;
	sha1_preprocess(input_string, processed_message, &processed_length);

	printf("Preprocessed Message blocks of 512 bits:\n");
	print_blocks(processed_message, processed_length);

	sha_1(hash_result, processed_message, initial_hash);
	printf("SHA-1 hash: %08x %08x %08x %08x %08x\n", hash_result[0],
			hash_result[1], hash_result[2], hash_result[3], hash_result[4]);

	uint8_t result = 1;
	for (int i = 0; i < 5; i++)
		if (hash_result[i] != expected_hash[i]) {
			result = 0;
			break;
		}

	if (result) {
		while (1) {
			LEDS.DATA_REG ^= 0xFF;
			for (delay = 0; delay < 1000000; delay++) {
			};
		}
	} else {
		LEDS.DATA_REG = 0xFF;
	}

	return 0;
}

void sha_1(uint32_t *hash_ptr, const uint8_t *message,
		const uint32_t *prev_hash) {
	size_t padded_length = pre_process_length;

	uint8_t padded_message[MAX_MESSAGE_LENGTH];
	memcpy(padded_message, message, pre_process_length);

	size_t num_blocks = padded_length / SHA1_BLOCK_SIZE;

	uint32_t hash_values[5];
	memcpy(hash_values, prev_hash, 5 * sizeof(uint32_t));

	for (size_t block = 0; block < num_blocks; block++) {
		const uint8_t *block_start = padded_message + block * SHA1_BLOCK_SIZE;

		uint32_t w[80];
		for (int i = 0; i < 16; i++) {
			w[i] = (block_start[i * 4] << 24) | (block_start[i * 4 + 1] << 16)
					| (block_start[i * 4 + 2] << 8) | block_start[i * 4 + 3];
		}
		for (int i = 16; i < 80; i++) {
			w[i] = LEFTROTATE(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
		}

		uint32_t a = hash_values[0];
		uint32_t b = hash_values[1];
		uint32_t c = hash_values[2];
		uint32_t d = hash_values[3];
		uint32_t e = hash_values[4];

		for (int i = 0; i < 80; i++) {
			uint32_t f, k;
			if (i < 20) {
				f = (b & c) | ((~b) & d);
				k = 0x5A827999;
			} else if (i < 40) {
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			} else if (i < 60) {
				f = (b & c) | (b & d) | (c & d);
				k = 0x8F1BBCDC;
			} else {
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}

			uint32_t temp = LEFTROTATE(a, 5) + f + e + k + w[i];
			e = d;
			d = c;
			c = LEFTROTATE(b, 30);
			b = a;
			a = temp;
		}

		hash_values[0] += a;
		hash_values[1] += b;
		hash_values[2] += c;
		hash_values[3] += d;
		hash_values[4] += e;
	}

	memcpy(hash_ptr, hash_values, 5 * sizeof(uint32_t));
}

void print_hex_and_binary(const uint8_t *data, size_t length) {
	printf("Hex: ");
	for (size_t i = 0; i < length; i++) {
		printf("%02X", data[i]);
	}
	printf("\nBinary: ");
	for (size_t i = 0; i < length; i++) {
		for (int j = 7; j >= 0; j--) {
			printf("%d", (data[i] >> j) & 1);
		}
		printf(" ");
	}
	printf("\n");
}

void sha1_preprocess(const char *message, uint8_t *processed_message,
		size_t *length) {
	size_t original_length = strlen(message);
	size_t new_length = original_length + 1 + 8
			+ (SHA1_BLOCK_SIZE - ((original_length + 1 + 8) % SHA1_BLOCK_SIZE));

	strcpy((char*) processed_message, message);
	processed_message[original_length] = 0x80;
	for (size_t i = original_length + 1; i < new_length - 8; i++) {
		processed_message[i] = 0;
	}

	uint64_t bit_length = original_length * 8;
	for (size_t i = 0; i < 8; i++) {
		processed_message[new_length - 8 + i] = (bit_length >> ((7 - i) * 8))
				& 0xFF;
	}

	*length = new_length;
	pre_process_length = new_length;
}

void print_blocks(const uint8_t *data, size_t length) {
	for (size_t i = 0; i < length / SHA1_BLOCK_SIZE; i++) {
		printf("Block %zu:\n", i + 1);
		print_hex_and_binary(data + i * SHA1_BLOCK_SIZE, SHA1_BLOCK_SIZE);
		printf("\n");
	}
}
