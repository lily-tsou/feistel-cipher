#include<fstream>
#include<iostream>
#include<array>
#include<string>

using namespace std;

const array<array<uint8_t, 16>, 16> FTABLE = 
{{{0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3, 0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9},
  {0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28},
  {0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53},
  {0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2},
  {0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8},
  {0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90},
  {0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76},
  {0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d},
  {0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18},
  {0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4},
  {0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40},
  {0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5},
  {0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2},
  {0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8},
  {0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac},
  {0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46}}};

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
