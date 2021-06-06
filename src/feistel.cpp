#include <fstream>
#include <iostream>
#include <array>
#include <string>
#include "ftable.h"

using namespace std;

void write_file_as_hex(array<uint16_t, 4> buffer, char *output_file){
  FILE * file_out;
  file_out = fopen(output_file, "a");

  for (int i = 0; i < 4; i++)
    fprintf(file_out, "%04x", buffer[i]);
  fprintf(file_out, "\n");

  fclose(file_out);
}

void write_file_as_ascii(array<uint16_t, 4> buffer, char *output_file){
  FILE * file_out;
  file_out = fopen(output_file, "a");

  for (int i = 0; i < 4; i++)
    fprintf(file_out, "%c%c", buffer[i] >> 8, buffer[i]);

  fclose(file_out);
}

/*
  Calculate the ftable index, and xor the value at that location with low_g.
  The ftable index is found by xoring high_g with the key, and using
  the high-order 4 bits to index the row and the low order 4 bits to index
  the column.
*/
uint8_t xor_ftable_with_g(array<array<uint8_t, 12>, 20> subkeys, uint8_t high_g, uint8_t low_g, int round, int key_index){
  uint8_t ftable_index = high_g ^ subkeys[round][key_index];
  uint8_t i = ftable_index >> 4;
  uint8_t j = ftable_index  & 0x0f;
  return FTABLE[i][j] ^ low_g;
}

/*
  Find G using the ftable, subkeys and block0 (the first block of the current round)
  g1 = high 8 bits of block0
  g2 = low 8 bits of block0
  Returns g5 concatenated with g6.
*/
uint16_t get_g(array<array<uint8_t, 12>, 20> subkeys, uint16_t block0, int key_offset, int round){
  uint8_t g1 = short(block0 >> 8);
  uint8_t g2 = block0 & 0x00ff;
  uint8_t g3 = xor_ftable_with_g(subkeys, g2, g1, round, key_offset + 0);
  uint8_t g4 = xor_ftable_with_g(subkeys, g3, g2, round, key_offset + 1);
  uint8_t g5 = xor_ftable_with_g(subkeys, g4, g3, round, key_offset + 2);
  uint8_t g6 = xor_ftable_with_g(subkeys, g5, g4, round, key_offset + 3);
  return g5 << 8 | g6;
}

/*
  Uses a single round of subkeys to computer F0 and F1.
  F0 = (t0 + 2t1 + concatenate(key[8], key[9])) mod 2^16
  F1 = (2t0 + t1 + concatenate(key[10], key[11])) mod 2^16
*/
array<uint16_t, 2> get_f(array<array<uint8_t, 12>, 20> subkeys, uint16_t block0, uint16_t block1, int round){ 
  array<uint16_t, 2> f;
  uint16_t t0 = get_g(subkeys, block0, 0, round);
  uint16_t t1 = get_g(subkeys, block1, 4, round);
  f[0] = (t0 + (2*t1) + (subkeys[round][8] << 8 | subkeys[round][9])) % 65536;
  f[1] = ((2* t0) + t1 + (subkeys[round][10] << 8 | subkeys[round][11])) % 65536;
  return f;
}

void left_rotate_one_bit(array<uint8_t, 10>& key){
  uint8_t high_bit = key[9] >> 7;
  
  for(int i = 9; i > 0; i--)
    key[i] = (key[i] << 1) | key[i - 1] >> 7;
  
  key[0] = key[0] << 1 | high_bit;
}

uint8_t get_byte(array<uint8_t, 10> key, int position){
  int i = position % 10;
  return key[i];
}

/*
  Whiten four blocks of 16-bit words with the first 64 bits of the key.
*/
array<uint16_t, 4> get_whitened_blocks(array<uint8_t, 10> key, array<uint16_t, 4>  input_blocks) {
  array<uint16_t, 4> output_blocks;

  int index = 9;
  for(int i = 0; i < 4; i++){
    uint16_t key_bytes = key[index--] << 8 | key[index--];
    output_blocks[i] = key_bytes ^ input_blocks[i];
  }

  return output_blocks;
}

array<uint16_t, 4> concat_chars_as_hex(array<uint8_t, 8> buffer){
  array<uint16_t, 4> hex_chars;
  
  for(int i = 0; i < 4; i++)
    hex_chars[i] = (buffer[i*2] << 8 | buffer[i*2+1]);
  
  return hex_chars;
}

/*
  Generate and return 12 subkeys for a single round of encryption
*/
array<uint8_t, 12> get_subkeys_for_round(array<uint8_t, 10>& key, int round){
  array<uint8_t, 12> round_keys;

  for(int i = 0; i < 12; i++){
    round_keys[i] = get_byte(key, 4*round + (i+4)%4);
    left_rotate_one_bit(key);
  }
  
  return round_keys;
}

/*
  Generate and return subkeys for 20 rounds of encryption/decryption
*/
array<array<uint8_t, 12>, 20> get_all_subkeys(array<uint8_t, 10>& key){  
  array<array<uint8_t, 12>, 20> subkeys;
  left_rotate_one_bit(key);

  for(int i = 0; i < 20; i++)
    subkeys[i] = get_subkeys_for_round(key, i);

  return subkeys;
}

array<uint8_t, 10> get_key(){
  FILE * key_in;
  key_in = fopen("key.txt", "rt");
  array<uint8_t, 10> key;
  unsigned int hex_digits;

  int items_read = fscanf(key_in, "%2x", &hex_digits);
  int i = 9;
  key[i--] = hex_digits;
  while (items_read != EOF && i >= 0){
    items_read = fscanf(key_in, "%2x", &hex_digits);
    key[i] = hex_digits;
    i--;
  }

  fclose(key_in);
  return key;
}

/*
  A single round of encryption/decryption

  Pass blocks at positions 0 and 1 into f() and XOR the results with blocks at 
  2 and 3 to become the new block position 1 and 2. The old block position 0 and 1 now 
  become positions 2 and 3.

*/
void process_single_round(array<uint16_t, 4> round_blocks, array<array<uint8_t, 12>, 20> subkeys, int round){
  uint16_t temp_r2 = round_blocks[0];
  uint16_t temp_r3 = round_blocks[1];
  array<uint16_t, 2> f = get_f(subkeys, round_blocks[0], round_blocks[1], round);
  round_blocks[0] = f[0] ^ round_blocks[2];
  round_blocks[1] = f[1] ^ round_blocks[3];
  round_blocks[2] = temp_r2;
  round_blocks[3] = temp_r3;
}

/*
  Main Feistel cipher portion to run encryption and decryption.
  Encryption and decryption are the same mechanisms, with
  encryption using the keys in the order they were created and
  decryption using the keys in reverse order.
  All blocks are whitened at the start of their first round. After
  encrption and decryption, the blocks are rearranged to undo
  their last swap and are whitened again with the key before 
  being written to a file.
*/
void process_all_rounds(
  array<uint8_t, 10> key, 
  array<array<uint8_t, 12>, 20> subkeys, 
  array<uint8_t, 8> buffer, 
  char option, 
  char *output_file
){
  array<uint16_t, 4> input = concat_chars_as_hex(buffer);
  array<uint16_t, 4> round_blocks = get_whitened_blocks(key, input);

  if(option == 'e')
    for(int i = 0; i < 20; i++)
      process_single_round(round_blocks, subkeys, i);
  else if(option == 'd')
    for(int i = 19; i >= 0; i--)
      process_single_round(round_blocks, subkeys, i);

  array<uint16_t, 4> temp_blocks;
  for(int i = 0; i < 4; i++)
    temp_blocks[i] = round_blocks[(i+2)%4];

  array<uint16_t, 4> processed_blocks = get_whitened_blocks(key, temp_blocks);

  if(option == 'e')
    write_file_as_hex(processed_blocks, output_file);
  else if(option == 'd')
    write_file_as_ascii(processed_blocks, output_file);

  buffer.fill(0);
}

/*
  Encrypt a file with a supplied 80-bit key.
  Read the input plaintext file as ascii characters. The plaintext file must be 
  read into an 8-bit buffer before concatenating together two groups of hex 
  digits into 16-bit words in order to keep the bytes in order on a little 
  endian machine.
  Generate all subkeys for 20 rounds of encryption and call process_rounds() 
  on each block.
  If the input is not a multiple of 64-bits, then padding will be added to
  the end of the last block to extend it to be a multiple of 64. All padded
  bits will be 0s.
*/
void encrypt(char *input_file, char *output_file){
  FILE * file_in;
  file_in = fopen(input_file, "r");
  array<uint8_t, 8>  buffer;
  buffer.fill(0);
  array<uint8_t, 10> start_key = get_key();
  array<uint8_t, 10> key = start_key;
  array<array<uint8_t, 12>, 20> subkeys = get_all_subkeys(start_key);

  int items_read = fread(&buffer, 1, 8, file_in);
  while(items_read > 0){
    array<uint16_t, 4>  plaintext_input = concat_chars_as_hex(buffer);
    process_all_rounds(key, subkeys, buffer, 'e', output_file);
    buffer.fill(0);
    items_read = fread(&buffer, 1, 8, file_in);
  }

  fclose(file_in);
}

/*
  Decrypt a file with a supplied 80-bit key.
  Read the input cipher file and key as hex. The cipher file must be read 
  into an 8-bit buffer before concatenating together two groups of hex 
  digits into 16-bits word in order to keep the bytes in order on a little 
  endian machine.
  Generate all subkeys for 20 rounds of decryption and call process_rounds() 
  on each block which will revert the bits to their original state prior to 
  encryption.
*/
void decrypt(char *input_file, char *output_file){
  FILE * file_in;
  file_in = fopen(input_file, "rt");
  array<uint8_t, 8>  buffer;
  buffer.fill(0);
  unsigned int hex_digits;
  array<uint8_t, 10> start_key = get_key();
  array<uint8_t, 10> key = start_key;
  array<array<uint8_t, 12>, 20> subkeys = get_all_subkeys(start_key);

  int items_read = fscanf(file_in, "%2x", &hex_digits);
  while(items_read > 0){
    int i = 0;
    buffer[i++] = hex_digits;
    while (items_read > 0 && i < 8){
      items_read = fscanf(file_in, "%2x", &hex_digits);
      buffer[i] = hex_digits;
      i++;
    }

    process_all_rounds(key, subkeys, buffer, 'd', output_file);
    buffer.fill(0);
    items_read = fscanf(file_in, "%2x", &hex_digits);
  }

  fclose(file_in);
}

int main(int argc, char ** argv) {
  if(argc < 4){
    cout << "Must include [e]ncrypt or [d]ecrypt option " 
      "and an input file and output file." << endl;
    return -1;
  }

  char option = *argv[1];
  char* input_file = argv[2];  
  char* output_file = argv[3];  

  if(option == 'e')
    encrypt(input_file, output_file);

  else
    decrypt(input_file, output_file);

  return 0;
}
