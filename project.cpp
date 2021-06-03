#include<stdio.h>
#include<math.h>
#include<ios>
#include<fstream>
#include<iostream>
#include<string>
#include<bitset>
#include<array>


using namespace std;
uint8_t unrotated_key[10] = {0};
unsigned short w[4] = {0};
unsigned short r[4] = {0};
unsigned short c[4] = {0};
unsigned short y[4] = {0};
uint8_t ftable [16][16] = 
{{0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3, 0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9},
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
  {0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46}};


uint8_t get_byte(array<uint8_t, 10>&key, int position){
  int i = position % 10;
  return key[i];
}

void rotate(array<uint8_t, 10>& key){
  //hold onto first bit that will be shifted out
  char rotate_bit = key[9] >> 7;

  //shift all bytes and concatonate with the first bit of the byte to the right of it
  for(int i = 9; i > 0; i--){
    key[i] = (key[i] << 1) | key[i - 1] >> 7;
  }

  //add the saved bit to the end of the key
  key[0] = key[0] << 1 | rotate_bit;
}

void gen_single_round_keys(array<uint8_t, 10>& key, array<array<uint8_t, 12>, 20>& subkeys, int round){
  //find the 12 subkeys based on the current rotated key, rotate each round (12x)
  for(int i = 0; i < 12; i++){
    subkeys[round][i] = get_byte(key, 4*round + (i+4)%4);
    rotate(key);
  }
}


array<array<uint8_t, 12>, 20> gen_all_round_keys(array<uint8_t, 10>& key){  
  array<array<uint8_t, 12>, 20> subkeys;

  rotate(key);

  for(int i = 0; i < 20; i++){
    gen_single_round_keys(key, subkeys, i);
  }

  return subkeys;
}


uint8_t find_ftable(array<array<uint8_t, 12>, 20>& subkeys, unsigned char high_g, unsigned char low_g, int round, int key_index){
  //generage 8 bytes that correspond to the index
  uint8_t ftable_index = high_g ^ subkeys[round][key_index];


  //split ftable index into two parts: i and j to index into the ftable
  unsigned int i = ftable_index >> 4;
  unsigned int j = ftable_index  & 0x0f;

  //return the i,jth index of the ftable xor low_g
  uint8_t freturn = ftable[i][j] ^ low_g;

  return freturn;

}

unsigned short G(array<array<uint8_t, 12>, 20>& subkeys, unsigned short r0, int key_offset, int round){
  uint8_t g1 = short(r0 >> 8);
  uint8_t g2 = r0 & 0x00ff;
  uint8_t g3 = find_ftable(subkeys, g2, g1, round, key_offset + 0);
  uint8_t g4 = find_ftable(subkeys, g3, g2, round, key_offset + 1);
  uint8_t g5 = find_ftable(subkeys, g4, g3, round, key_offset + 2);
  uint8_t g6 = find_ftable(subkeys, g5, g4, round, key_offset + 3);

  //concat g5 and g6 to return
  unsigned short greturn = g5 << 8 | g6;

  return greturn;

  //uint8_t g3_index = 
}

void F(array<array<uint8_t, 12>, 20>& subkeys, unsigned short block0, unsigned short block1, int round, unsigned short &f0, unsigned short &f1){  
  unsigned short t0 = G(subkeys, block0, 0, round);
  unsigned short t1 = G(subkeys, block1, 4, round);

  f0 = (t0 + (2*t1) + (subkeys[round][8] << 8 | subkeys[round][9])) % 65536;
  f1 = ((2* t0) + t1 + (subkeys[round][10] << 8 | subkeys[round][11])) % 65536;
}

array<uint16_t, 2> get_f(array<array<uint8_t, 12>, 20>& subkeys, unsigned short block0, unsigned short block1, int round){ 
  array<uint16_t, 2> f;
  unsigned short t0 = G(subkeys, block0, 0, round);
  unsigned short t1 = G(subkeys, block1, 4, round);
  f[0] = (t0 + (2*t1) + (subkeys[round][8] << 8 | subkeys[round][9])) % 65536;
  f[1] = ((2* t0) + t1 + (subkeys[round][10] << 8 | subkeys[round][11])) % 65536;
  return f;
}

//TODO change name (e.g. get_key_as_hex())
//TODO Pass in file name? Open/close inside or outside of file?
array<uint8_t, 10> get_key(){
  array<uint8_t, 10> key;
  FILE * keystream;
  keystream = fopen("key.txt", "rt");

  // Key is read in as 10 bytes (20 ascii characters interpreted as hex digits), 
  // with K[0] as the lowest order byte (the farthest right two digits in the file)
  int i = 9;
  unsigned hex;
  int h = fscanf(keystream, "%2x", &hex);
  key[i--] = hex;

  while (h != EOF && i >= 0){
    h = fscanf(keystream, "%2x", &hex);
    key[i] = hex;
    i--;
  }

  fclose(keystream);


  //Get rid if this if time -- original key should not be necessary, key is rotated back to beginning
  for(int i = 0; i < 10; i++){
    unrotated_key[i] = key[i];
    cout << key[i] << endl;
  }

  return key;
}

//TODO can use for decryption?
array<uint16_t, 4> get_blocks_xored_with_key(array<uint16_t, 4>  input_blocks) {
  array<uint16_t, 4> output_blocks;
  int index = 9;
  for(int i = 0; i < 4; i++){
    uint16_t key_bytes = unrotated_key[index--] << 8 | (unrotated_key[index--]);
    output_blocks[i] = key_bytes ^ input_blocks[i];
  }
  return output_blocks;
}

void encrypt(array<array<uint8_t, 12>, 20>& subkeys){
  FILE * file_in;
  file_in = fopen("text.txt", "r");
  FILE * file_out;
  file_out = fopen("output.txt", "a");

  // A buffer is required for bytes to be read in
  // correct order on a Little Endian machine
  array<uint8_t, 8>  buffer;
  buffer.fill(0);
  array<uint16_t, 4>  plaintext_input;
  plaintext_input.fill(0);

  int items_read = fread(&buffer, 1, 8, file_in);
  while(items_read > 0){
    for(int i = 0; i < 4; i++){
      plaintext_input[i] = (buffer[i*2] << 8 | buffer[i*2+1]);
    }
    array<uint16_t, 4> round_blocks = get_blocks_xored_with_key(plaintext_input);

    //-------------BLOCK ENCRYPTION--------------//
    for(int i = 0; i < 20; i++){
      unsigned short temp_r2 = round_blocks[0];
      unsigned short temp_r3 = round_blocks[1];
      array<uint16_t, 2> f = get_f(subkeys, round_blocks[0], round_blocks[1], i);
      round_blocks[0] = f[0] ^ round_blocks[2];
      round_blocks[1] = f[1] ^ round_blocks[3];
      round_blocks[2] = temp_r2;
      round_blocks[3] = temp_r3;
    }

    array<uint16_t, 4> temp_blocks;
    for(int i = 0; i < 4; i++){
      temp_blocks[i] = round_blocks[(i+2)%4];
    }

    array<uint16_t, 4> cipher = get_blocks_xored_with_key(temp_blocks);

    //---------------WRITE FILE-----------------//
    for (int i = 0; i < 4; i++)
    {
      fprintf(file_out, "%04x", cipher[i]);
    }
    fprintf(file_out, "\n");

    // Add padding if the next read is less than 8 bytes
    buffer.fill(0);
    items_read = fread(&buffer, 1, 8, file_in);
  }

  fclose(file_in);
  fclose(file_out);
}

int main(int argc, char ** argv) {
  if(argc < 2){
    cout << "Must include e/d option." << endl;
    return -1;
  }

  char option;

  option = *argv[1];

  //Open output file

  array<uint8_t, 10> key = get_key();

  //------------SUBKEY GENERATION---------------//
  array<array<uint8_t, 12>, 20> subkeys = gen_all_round_keys(key);



  if(option == 'e'){
    encrypt(subkeys);
    return(0);
  }

  else{
    FILE * cipherstream;
    cipherstream = fopen("cipher.txt", "rt");
    FILE * output;
    output = fopen("output.txt", "a");

    uint8_t buffer[8] = {0};

    /*
       for(int i = 0; i < 8; i++){
       buffer[i] = 0;
       }*/

    unsigned int hex;
    int x = fscanf(cipherstream, "%2x", &hex);

    //added
    while(x > 0){
      int i = 0;
      buffer[i++] = hex;

      while (x > 0 && i < 8){
        x = fscanf(cipherstream, "%2x", &hex);
        buffer[i] = hex;
        i++;
      }

      //W0 = buffer[0] and buffer[1], W1 = buffer[2] and buffer[3], etc.
      for(int i = 0; i < 4; i++){
        w[i] = (buffer[i*2] << 8 | buffer[i*2+1]);
      }

      //XOR W with key to create R0....R3
      int key_i = 9;
      for(int i = 0; i < 4; i++){
        unsigned short concat_k = unrotated_key[key_i--] << 8 | (unrotated_key[key_i--]);
        r[i] = concat_k ^ w[i];
      }

      //-------------BLOCK ENCRYPTION--------------//
      for(int i = 19; i > -1; i--){
        unsigned short temp_r2 = r[0];
        unsigned short temp_r3 = r[1];
        unsigned short f0;
        unsigned short f1;

        F(subkeys, r[0], r[1], i, f0, f1);

        r[0] = f0 ^ r[2];
        r[1] = f1 ^ r[3];
        r[2] = temp_r2;
        r[3] = temp_r3;
      }

      for(int i = 0; i < 4; i++){
        y[i] = r[(i+2)%4];
      }

      key_i = 9;
      for(int i = 0; i < 4; i++){
        unsigned short concat_k = unrotated_key[key_i--] << 8 | (unrotated_key[key_i--]);
        c[i] = concat_k ^ y[i];
      }


      //---------------WRITE FILE-----------------//
      for (int i = 0; i < 4; i++)
      {
        fprintf(output, "%c%c", (*(c+i)) >> 8, (*(c+i)));
      }

      //empty buffer, will add padding if the next read is less than 8
      for(int i = 0; i < 9; i++){
        buffer[i] = 0; 
      }

      x = fscanf(cipherstream, "%2x", &hex);
    }


    fclose(cipherstream);
    return(0);

  }
}
