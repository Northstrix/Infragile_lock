/*
Infragile lock
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://github.com/Northstrix/Infragile_lock
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ulwanski/sha512
https://github.com/madhephaestus/ESP32Servo
*/
#include <sys/random.h>
#include "mbedtls/md.h"
#include "SPIFFS.h"
#include "sha512.h"
#include "aes.h"
#include "serpent.h"
#include <ESP32Servo.h>
Servo myservo;
char ac = '0';
char bc = '0';
char cc = '0';
char dc = '0';
int opan = 0; // closed angle
int clan = 180; // open angle
int count;
byte tmp_st[8];
int m;
String dec_st;
uint8_t back_key[32];
uint8_t back_s_key[32];

String spart = "77UNCPM533p18T6ylFYIw5d3S60Utyc6alolm9zda7FZeJ2tLpgxGpz64tdXH3LMxdJYrUJT0";
char *keys[] = {"cc59c0ab7ec8efde71b187fb4b26f418d736b667abaaff9f79d424e5f9badf37"}; // Serpent's key
uint8_t key[32] = {
0x84,0xb3,0xee,0x2d,
0xd1,0x0a,0xba,0xc7,
0xcb,0x73,0x42,0xfd,
0x46,0x80,0xea,0xfc,
0xce,0x55,0xfa,0xcc,
0xbf,0xcb,0xad,0x0e,
0x4b,0x6c,0x1e,0xb7,
0x23,0x2c,0x92,0xce
};
uint8_t second_key[32] = {
0x72,0xd8,0x6c,0x1d,
0x87,0xa0,0xf5,0x10,
0x3d,0xb0,0x1b,0x0d,
0xe6,0xab,0x20,0x1d,
0xc6,0x5f,0x19,0xb2,
0x6f,0x06,0xf3,0xce,
0x76,0xac,0x13,0xcd,
0x1b,0xbd,0xf4,0x9c
};

void back_k(){
  for(int i = 0; i<32; i++){
    back_key[i] = key[i];
  }
}

void rest_k(){
  for(int i = 0; i<32; i++){
    key[i] = back_key[i];
  }
}

void back_s_k(){
  for(int i = 0; i<32; i++){
    back_s_key[i] = second_key[i];
  }
}

void rest_s_k(){
  for(int i = 0; i<32; i++){
    second_key[i] = back_s_key[i];
  }
}

void incr_key(){
  if(key[0] == 255){
    key[0] = 0;
    if(key[1] == 255){
      key[1] = 0;
      if(key[2] == 255){
        key[2] = 0;
        if(key[3] == 255){
          key[3] = 0;

  if(key[4] == 255){
    key[4] = 0;
    if(key[5] == 255){
      key[5] = 0;
      if(key[6] == 255){
        key[6] = 0;
        if(key[7] == 255){
          key[7] = 0;
          
  if(key[8] == 255){
    key[8] = 0;
    if(key[9] == 255){
      key[9] = 0;
      if(key[10] == 255){
        key[10] = 0;
        if(key[11] == 255){
          key[11] = 0;

  if(key[12] == 255){
    key[12] = 0;
    if(key[13] == 255){
      key[13] = 0;
      if(key[14] == 255){
        key[14] = 0;
        if(key[15] == 255){
          key[15] = 0;
        }
        else{
          key[15]++;
        }
        }
      else{
        key[14]++;
      }
    }
    else{
      key[13]++;
    }
  }
  else{
    key[12]++;
  }
          
        }
        else{
          key[11]++;
        }
        }
      else{
        key[10]++;
      }
    }
    else{
      key[9]++;
    }
  }
  else{
    key[8]++;
  }
          
        }
        else{
          key[7]++;
        }
        }
      else{
        key[6]++;
      }
    }
    else{
      key[5]++;
    }
  }
  else{
    key[4]++;
  }
          
        }
        else{
          key[3]++;
        }
        }
      else{
        key[2]++;
      }
    }
    else{
      key[1]++;
    }
  }
  else{
    key[0]++;
  }
}

void incr_second_key(){
  if(second_key[0] == 255){
    second_key[0] = 0;
    if(second_key[1] == 255){
      second_key[1] = 0;
      if(second_key[2] == 255){
        second_key[2] = 0;
        if(second_key[3] == 255){
          second_key[3] = 0;

  if(second_key[4] == 255){
    second_key[4] = 0;
    if(second_key[5] == 255){
      second_key[5] = 0;
      if(second_key[6] == 255){
        second_key[6] = 0;
        if(second_key[7] == 255){
          second_key[7] = 0;
          
  if(second_key[8] == 255){
    second_key[8] = 0;
    if(second_key[9] == 255){
      second_key[9] = 0;
      if(second_key[10] == 255){
        second_key[10] = 0;
        if(second_key[11] == 255){
          second_key[11] = 0;

  if(second_key[12] == 255){
    second_key[12] = 0;
    if(second_key[13] == 255){
      second_key[13] = 0;
      if(second_key[14] == 255){
        second_key[14] = 0;
        if(second_key[15] == 255){
          second_key[15] = 0;
        }
        else{
          second_key[15]++;
        }
        }
      else{
        second_key[14]++;
      }
    }
    else{
      second_key[13]++;
    }
  }
  else{
    second_key[12]++;
  }
          
        }
        else{
          second_key[11]++;
        }
        }
      else{
        second_key[10]++;
      }
    }
    else{
      second_key[9]++;
    }
  }
  else{
    second_key[8]++;
  }
          
        }
        else{
          second_key[7]++;
        }
        }
      else{
        second_key[6]++;
      }
    }
    else{
      second_key[5]++;
    }
  }
  else{
    second_key[4]++;
  }
          
        }
        else{
          second_key[3]++;
        }
        }
      else{
        second_key[2]++;
      }
    }
    else{
      second_key[1]++;
    }
  }
  else{
    second_key[0]++;
  }
}

int gen_r_num(){
  char rnd_nmbr[128];
  char key[128];
  //String h = "";
  int res = 0;
  for(int i = 0; i<128; i++){
    int c = esp_random()%4;
    c += esp_random()%4;
    c += esp_random()%4;
    c += esp_random()%4;
    c += esp_random()%4;    
    int d = esp_random()%4;
    d += esp_random()%4;
    d += esp_random()%4;
    d += esp_random()%4;
    d += esp_random()%4;
    int z = esp_random()%4;
    z += esp_random()%4;
    z += esp_random()%4;
    z += esp_random()%4;
    z += esp_random()%4;
    int x = esp_random()%4;
    x += esp_random()%4;
    x += esp_random()%4;
    x += esp_random()%4;
    x += esp_random()%4;
    //Serial.println(z);
    //Serial.println(x);
    //Serial.println(c);
    //Serial.println(d);
    if(c != 0 && d != 0)
    res = (16*c)+d;
    if(c != 0 && d == 0)
    res = 16*c;
    if(c == 0 && d != 0)
    res = d;
    if(c == 0 && d == 0)
    res = 0;
    rnd_nmbr[i] = char(res);
    //Serial.println(res);
    if(z != 0 && x != 0)
    res = (16*z)+x;
    if(z != 0 && x == 0)
    res = 16*z;
    if(z == 0 && x != 0)
    res = x;
    if(z == 0 && x == 0)
    res = 0;
    key[i] = char(res);
    //Serial.println(res);
    //h += getChar(c);
    //h += getChar(d);
  }
  byte hmacResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
 
  const size_t payloadLength = strlen(rnd_nmbr);
  const size_t keyLength = strlen(key);            
 
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char *) key, keyLength);
  mbedtls_md_hmac_update(&ctx, (const unsigned char *) rnd_nmbr, payloadLength);
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);
  /*
  for(int i=0; i<32; i++){
  Serial.print(hmacResult[i] + " ");
  }
  */
  //Serial.print("Hash: ");
  int y = esp_random()%32;
  int rn = (int)hmacResult[y];
  return rn;
}

int getNum(char ch)
{
    int num=0;
    if(ch>='0' && ch<='9')
    {
        num=ch-0x30;
    }
    else
    {
        switch(ch)
        {
            case 'A': case 'a': num=10; break;
            case 'B': case 'b': num=11; break;
            case 'C': case 'c': num=12; break;
            case 'D': case 'd': num=13; break;
            case 'E': case 'e': num=14; break;
            case 'F': case 'f': num=15; break;
            default: num=0;
        }
    }
    return num;
}

char getChar(int num){
  char ch;
    if(num>=0 && num<=9)
    {
        ch = char(num+48);
    }
    else
    {
        switch(num)
        {
            case 10: ch='a'; break;
            case 11: ch='b'; break;
            case 12: ch='c'; break;
            case 13: ch='d'; break;
            case 14: ch='e'; break;
            case 15: ch='f'; break;
        }
    }
    return ch;
}

size_t hex2bin (void *bin, char hex[]) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  
  len = strlen (hex);
  
  if ((len & 1) != 0) {
    return 0; 
  }
  
  for (i=0; i<len; i++) {
    if (isxdigit((int)hex[i]) == 0) {
      return 0; 
    }
  }
  
  for (i=0; i<len / 2; i++) {
    sscanf (&hex[i * 2], "%2x", &x);
    p[i] = (uint8_t)x;
  } 
  return len / 2;
}

void split_by_eight(char plntxt[], int k, int str_len, bool add_aes){
  char plt_data[] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      plt_data[i] = plntxt[i+k];
  }
  char t_encr[16];
  for(int i = 0; i<8; i++){
      t_encr[i] = plt_data[i];
  }
  for(int i = 8; i<16; i++){
      t_encr[i] = gen_r_num();
  }
  encr_AES(t_encr, add_aes);
}

void encr_AES(char t_enc[], bool add_aes){
  uint8_t text[16];
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  aes_context ctx;
  aes_set_key(&ctx, key, key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; ++i) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for(int i = 0; i<8; i++){
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for(int i = 0; i<8; i++){
    R_half[i] = cipher_text[i+8];
  }
  for(int i = 8; i<16; i++){
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  serp_enc(L_half, add_aes);
  serp_enc(R_half, add_aes);
}

void serp_enc(char res[], bool add_aes){
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
      tmp_s[i] = res[i];
  }
  /*
   for (int i = 0; i < 16; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t *p;
  
  for (b=0; b<sizeof(keys)/sizeof(char*); b++) {
    hex2bin (key, keys[b]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
  if(add_aes == false){
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
    }
  }
  if(add_aes == true)
  encr_sec_AES(ct2.b);
  }
}

void encr_sec_AES(byte t_enc[]){
  uint8_t text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t second_key_bit[3] = {128, 192, 256};
  int i = 0;
  aes_context ctx;
  aes_set_key(&ctx, second_key, second_key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  for (i = 0; i < 16; ++i) {
    Serial.printf("%02x", cipher_text[i]);
  }
}

void split_dec(char ct[], int ct_len, int p, bool ch, bool add_r){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
    if(i+p > ct_len - 1){
      br = true;
      break;
    }
    if (i == 0){
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i] = 0;
    }
    else{
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i/2] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i/2] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i/2] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i/2] = 0;
    }
  }
    if(br == false){
      if(add_r == true){
      uint8_t ret_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t second_key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, second_key, second_key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 16; ++i) {
        res[i] = (char)ret_text[i];
      }
      }
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<sizeof(keys)/sizeof(char*); i++) {
    hex2bin (key, keys[i]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
    if (ch == false){
    for (int i=0; i<8; i++) {
      tmp_st[i] = char(ct2.b[i]);
    }
    }
    if (ch == true){
      decr_AES(ct2.b);
    }
  }
}

void decr_AES(byte sh[]){
  uint8_t ret_text[16];
  for(int i = 0; i<8; i++){
    ret_text[i] = tmp_st[i];
  }
  for(int i = 0; i<8; i++){
    ret_text[i+8] = sh[i];
  }
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(ret_text[i]);
        cipher_text[i] = c;
      }
      uint32_t key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, key, key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 8; ++i) {
        if (ret_text[i] != 0)
          dec_st += (char(ret_text[i]));
      }
}

void split_by_eight_for_AES(char plntxt[], int k, int str_len){
  char res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for(int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      res[i] = plntxt[i+k];
  }
  for(int i = 8; i<16; i++){
    res[i] = gen_r_num();
  }
  encr_AES_only(res);
}

void encr_AES_only(char t_enc[]){
  uint8_t text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  int i = 0;
  aes_context ctx;
  aes_set_key(&ctx, key, key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  for (i = 0; i < 16; ++i) {
    Serial.printf("%02x", cipher_text[i]);
  }
}

void split_dec_for_AES(char ct[], int ct_len, int p){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
    if(i+p > ct_len - 1){
      br = true;
      break;
    }
    if (i == 0){
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i] = 0;
    }
    else{
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i/2] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i/2] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i/2] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i/2] = 0;
    }
  }
    if(br == false){
      uint8_t ret_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, key, key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 8; ++i) {
        Serial.print(char(ret_text[i]));
      }
   }
}

void split_by_eight_for_Serpent_only(char plntxt[], int k, int str_len){
  char res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      res[i] = plntxt[i+k];
  }
  for (int i = 8; i < 16; i++){
      res[i] = gen_r_num();
  }
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
      tmp_s[i] = res[i];
  }
  /*
   for (int i = 0; i < 8; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t *p;
  
  for (b=0; b<sizeof(keys)/sizeof(char*); b++) {
    hex2bin (key, keys[b]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
  }
  }
}

void split_dec_for_Serpent_only(char ct[], int ct_len, int p){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
    if(i+p > ct_len - 1){
      br = true;
      break;
    }
    if (i == 0){
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i] = 0;
    }
    else{
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i/2] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i/2] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i/2] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i/2] = 0;
    }
  }
    if(br == false){
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<sizeof(keys)/sizeof(char*); i++) {
    hex2bin (key, keys[i]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
    for (int i=0; i<8; i++) {
      dec_st += char(ct2.b[i]);
    }
  }
}

void GenToken(){
  String tkn;
  int a = read_f("/a").toInt();
  int b = read_f("/b").toInt();
  int c = read_f("/c").toInt();
  int d = read_f("/d").toInt();
  int e = read_f("/e").toInt();
  int f = read_f("/f").toInt();
  int g = read_f("/g").toInt();
  int j = read_f("/j").toInt();
  int k = read_f("/k").toInt();
  int l = read_f("/l").toInt();
  /*
  Serial.println();
  Serial.print(a);
  Serial.print(" ");
  Serial.print(b);
  Serial.print(" ");
  Serial.print(c);
  Serial.print(" ");
  Serial.print(d);
  Serial.print(" ");
  Serial.print(e);
  Serial.print(" ");
  Serial.print(f);
  Serial.print(" ");
  Serial.print(g);
  Serial.print(" ");
  Serial.print(j);
  Serial.print(" ");
  Serial.print(k);
  Serial.print(" ");
  Serial.println(l);
  */
  /*
  Serial.print(read_f("/a"));
  Serial.print(" ");
  Serial.print(read_f("/b"));
  Serial.print(" ");
  Serial.print(read_f("/c"));
  Serial.print(" ");
  Serial.print(read_f("/d"));
  Serial.print(" ");
  Serial.print(read_f("/e"));
  Serial.print(" ");
  Serial.print(read_f("/f"));
  Serial.print(" ");
  Serial.print(read_f("/g"));
  Serial.print(" ");
  Serial.print(read_f("/j"));
  Serial.print(" ");
  Serial.print(read_f("/k"));
  Serial.print(" ");
  Serial.println(read_f("/l"));
  */
  while(1){
    tkn = "";
    if (a > 31)
      tkn += char(a);
    if (b > 31)
      tkn += char(b);
    if (c > 31)
      tkn += char(c);
    if (d > 31)
      tkn += char(d);
    if (e > 31)
      tkn += char(e);
    if (f > 31)
      tkn += char(f);
    if (g > 31)
      tkn += char(g);
    if (j > 31)
      tkn += char(j);
    if (k > 31)
      tkn += char(k);
    if (l > 31)
      tkn += char(l);
    tkn += spart;
    int str_len = tkn.length() + 1;
    char input_arr[str_len];
    tkn.toCharArray(input_arr, str_len);
    std::string str = "";
    if(str_len > 1){
      for(int i = 0; i<str_len-1; i++){
        str += input_arr[i];
      }
    }
    String h = sha512( str ).c_str();
    char h_arr[129];
    h.toCharArray(h_arr, 129);
    if (h_arr[0] == ac && h_arr[1] == bc && h_arr[2] == cc && h_arr[3] == dc){
      //Serial.println(tkn);
      encr_token(tkn);
      //Serial.println();
      /*
      for (int i = 0; i<128; i++){
        Serial.print(h_arr[i]);
      }
      Serial.println();
      */
    }
    a++;
    if (a > 126){
      a = 32;
      b++;
    }
    if (b > 126){
      b = 32;
      c++;
    }
    if (c > 126){
      c = 32;
      d++;
    }
    if (d > 126){
      d = 32;
      e++;
    }
    if (e > 126){
      e = 32;
      f++;
    }
    if (f > 126){
      f = 32;
      g++;
    }
    if (g > 126){
      g = 32;
      j++;
    }
    if (j > 126){
      j = 32;
      k++;
    }
    if (k > 126){
      k = 32;
      l++;
    }
    if (l > 126){
      Serial.println("No more combinations to try!");
      write_f("/a", String(a));
      write_f("/b", String(b));
      write_f("/c", String(c));
      write_f("/d", String(d));
      write_f("/e", String(e));
      write_f("/f", String(f));
      write_f("/g", String(g));
      write_f("/j", String(j));
      write_f("/k", String(k));
      write_f("/l", String(l));
      break;
    }
    if (digitalRead(15) == LOW){
      /*
      Serial.print(a);
      Serial.print(" ");
      Serial.print(b);
      Serial.print(" ");
      Serial.print(c);
      Serial.print(" ");
      Serial.print(d);
      Serial.print(" ");
      Serial.print(e);
      Serial.print(" ");
      Serial.print(f);
      Serial.print(" ");
      Serial.print(g);
      Serial.print(" ");
      Serial.print(j);
      Serial.print(" ");
      Serial.print(k);
      Serial.print(" ");
      Serial.println(l);
      */
      write_f("/a", String(a));
      write_f("/b", String(b));
      write_f("/c", String(c));
      write_f("/d", String(d));
      write_f("/e", String(e));
      write_f("/f", String(f));
      write_f("/g", String(g));
      write_f("/j", String(j));
      write_f("/k", String(k));
      write_f("/l", String(l));
      break;
    }
  }
}

String read_f(String name){
  File file = SPIFFS.open(name);
  if(!file){
    Serial.println("Failed to open file for reading");
    return "";
  }
  String r = "";
  while(file.available()){
    r += (char(file.read()));
  }
  file.close();
  return r;
}

void write_f(String name, String cont){
  File file = SPIFFS.open(name, FILE_WRITE);
 
  if (!file) {
    Serial.println("There was an error opening the file for writing");
    return;
  }
  if (file.print(cont)) {
    //Serial.println("File was written");
  } else {
    Serial.println("File write failed");
  }
 
  file.close();
}

void encr_token(String inp_str){
  back_k();
  back_s_k();
  int str_len = inp_str.length() + 1;
  char char_array[str_len];
  inp_str.toCharArray(char_array, str_len);
  Serial.println("");
  int p = 0;
  while(str_len > p+1){
    incr_key();
    incr_second_key();
    split_by_eight(char_array, p, str_len, true);
    p+=8;
  }
  rest_k();
  rest_s_k();
}

int validate_sequence(String input){
  int crct = 1;
  int spart_len = spart.length();
  char spart_arr[spart_len + 1];
  spart.toCharArray(spart_arr, spart_len + 1);
  
  int inp_len = input.length();
  char inp_arr[inp_len + 1];
  input.toCharArray(inp_arr, inp_len + 1);

  int diff = inp_len - spart_len;
  /*
  Serial.println(spart_len);
  Serial.println(inp_len);
  Serial.println(diff);
  */
  for (int i = spart_len - 1; i > -1; i--) {
    if (spart_arr[i] == inp_arr[i+diff]){
      crct *= 1;
    }
    else{
      crct = -1;
    }
  }
  return crct;
}

void hash_using_SHA512(String input){
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  std::string str = "";
  if(str_len > 1){
    for(int i = 0; i<str_len-1; i++){
      str += input_arr[i];
    }
  }
  String h = sha512( str ).c_str();
  char h_arr[129];
  h.toCharArray(h_arr, 129);
  int vlk = validate_sequence(input);
  if (h_arr[0] == ac && h_arr[1] == bc && h_arr[2] == cc && h_arr[3] == dc && vlk == 1){
    File file = SPIFFS.open("/0");
    if(!file){
      Serial.println("Failed to open file for reading");
    }
    String zfc = "";
    while(file.available()){
      zfc += (char(file.read()));
    }
    file.close();

    file = SPIFFS.open("/1");
    if(!file){
      Serial.println("Failed to open file for reading");
    }
    String ffc = "";
    while(file.available()){
      ffc += (char(file.read()));
    }
    file.close();

    file = SPIFFS.open("/2");
    if(!file){
      Serial.println("Failed to open file for reading");
    }
    String sfc = "";
    while(file.available()){
      sfc += (char(file.read()));
    }
    file.close();

    file = SPIFFS.open("/3");
    if(!file){
      Serial.println("Failed to open file for reading");
    }
    String tfc = "";
    while(file.available()){
      tfc += (char(file.read()));
    }
    file.close();

    file = SPIFFS.open("/4");
    if(!file){
      Serial.println("Failed to open file for reading");
    }
    String frfc = "";
    while(file.available()){
      frfc += (char(file.read()));
    }
    file.close();

    file = SPIFFS.open("/5");
    if(!file){
      Serial.println("Failed to open file for reading");
    }
    String fifc = "";
    while(file.available()){
      fifc += (char(file.read()));
    }
    file.close();

    file = SPIFFS.open("/6");
    if(!file){
      Serial.println("Failed to open file for reading");
    }
    String sixfc = "";
    while(file.available()){
      sixfc += (char(file.read()));
    }
    file.close();

    file = SPIFFS.open("/7");
    if(!file){
      Serial.println("Failed to open file for reading");
    }
    String sevfc = "";
    while(file.available()){
      sevfc += (char(file.read()));
    }
    file.close();

    file = SPIFFS.open("/8");
    if(!file){
      Serial.println("Failed to open file for reading");
    }
    String egfc = "";
    while(file.available()){
      egfc += (char(file.read()));
    }
    file.close();

    file = SPIFFS.open("/9");
    if(!file){
      Serial.println("Failed to open file for reading");
    }
    String nfc = "";
    while(file.available()){
      nfc += (char(file.read()));
    }
    file.close();

    if (zfc != input && ffc != input && sfc != input && tfc != input && frfc != input && fifc != input && sixfc != input && sevfc != input && egfc != input && nfc != input){
      open_lock();
    }
    else{
      Serial.println("That key was taken out of circulation!");
    }
  }
  else{
    Serial.println("Invalid key");
  }
}

void open_lock(){
  Serial.println("Open");
  myservo.write(opan);
}

void setup() {
  Serial.begin(115200);
  if (!SPIFFS.begin(true)) {
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }
  pinMode(15, INPUT);
  m = 2;
  dec_st = "";
  ESP32PWM::allocateTimer(0);
  ESP32PWM::allocateTimer(1);
  ESP32PWM::allocateTimer(2);
  ESP32PWM::allocateTimer(3);
  myservo.setPeriodHertz(50);
  myservo.attach(2, 500, 2400);
  myservo.write(clan);
}

void loop() {
    Serial.println();
    back_k();
    back_s_k();
    Serial.println("What do you want to do?");
    Serial.println("1.Generate keys");
    Serial.println("2.Open the lock");
    Serial.println("3.Blacklist the key");
    Serial.println("4.Close the lock");
    Serial.println("5.Encrypt data using AES + Serpent + AES in counter mode");
    Serial.println("6.Decrypt data using AES + Serpent + AES in counter mode");
    Serial.println("7.Set AES to 128-bit mode");
    Serial.println("8.Set AES to 192-bit mode");
    Serial.println("9.Set AES to 256-bit mode");
    Serial.println("10.Increment key (IV) n times");
    Serial.println("11.Test RNG");
    Serial.println("12.Derive part of the key from the string");
    Serial.println("13.Generate random ASCII strings");
    Serial.println("14.Hash data with SHA-512");
    Serial.println("15.Save data into the file");
    Serial.println("16.Load record from the file");
    Serial.println("17.Delete file");
    Serial.println("18.List all stored files");
    while (!Serial.available()) {
    if (digitalRead(15) == LOW)
      myservo.write(clan);
    }
    int x = Serial.parseInt();
    if(x == 1){
      Serial.println("Key generation process started.\nIt might take a while.");
      GenToken();
    }
    if(x == 2){
      dec_st = "";
      String ct;
      Serial.println("Paste the encrypted key");
      while (!Serial.available()) {}
      ct = Serial.readString();
      int ct_len = ct.length() + 1;
      char ct_array[ct_len];
      ct.toCharArray(ct_array, ct_len);
      int ext = 0;
      count = 0;
      bool ch = false;
      while(ct_len > ext){
      if(count%2 == 1 && count !=0)
        ch = true;
      else{
        ch = false;
        incr_key();
        incr_second_key();
      }
      split_dec(ct_array, ct_len, 0+ext, ch, true);
      ext+=32;
      count++;
      }
      rest_k();
      rest_s_k();
      //Serial.println(dec_st);
      hash_using_SHA512(dec_st);
      dec_st = "";
    }
    if(x == 3){
      dec_st = "";
      String ct;
      Serial.println("Paste the encrypted key to add it to the blacklist");
      while (!Serial.available()) {}
      ct = Serial.readString();
      int ct_len = ct.length() + 1;
      char ct_array[ct_len];
      ct.toCharArray(ct_array, ct_len);
      int ext = 0;
      count = 0;
      bool ch = false;
      while(ct_len > ext){
      if(count%2 == 1 && count !=0)
        ch = true;
      else{
        ch = false;
          incr_key();
          incr_second_key();
      }
      split_dec(ct_array, ct_len, 0+ext, ch, true);
      ext+=32;
      count++;
      }
      rest_k();
      rest_s_k();
      //Serial.println(dec_st);
      Serial.println("Choose the slot to put the blacklisted key in.\nEnter the number from 0 to 9\nEnter c to cancel.");
      for (int i = 0; i < 10; i++){
        File file = SPIFFS.open("/" + String(i));
        String cntnt = "";
        while(file.available()){
          cntnt += (char(file.read()));
        }
        if(cntnt == "0"){
          Serial.println("[" + String(i) + "] - Empty");
        }
        else {
          Serial.println("[" + String(i) + "] - Full");
        }
        file.close();
      }
      while (!Serial.available()) {}
      String slt = Serial.readString();
      if (slt != "c")
        write_f("/" + slt, dec_st);
      dec_st = "";
    }
    if(x == 4){
      myservo.write(clan);
    }
    if(x == 5){
      Serial.println("Enter plaintext:");
      String inp_str;
      while (!Serial.available()) {}
      inp_str = Serial.readString();
      int str_len = inp_str.length() + 1;
      char char_array[str_len];
      inp_str.toCharArray(char_array, str_len);
      Serial.println("Ciphertext:");
      int p = 0;
      while(str_len > p+1){
        incr_key();
        incr_second_key();
        split_by_eight(char_array, p, str_len, true);
        p+=8;
      }
      rest_k();
      rest_s_k();
    }
    if(x == 6){
      dec_st = "";
      String ct;
      Serial.println("Paste ciphertext");
      while (!Serial.available()) {}
      ct = Serial.readString();
      int ct_len = ct.length() + 1;
      char ct_array[ct_len];
      ct.toCharArray(ct_array, ct_len);
      int ext = 0;
      count = 0;
      bool ch = false;
      Serial.println("Plaintext");
      while(ct_len > ext){
      if(count%2 == 1 && count !=0)
        ch = true;
      else{
        ch = false;
          incr_key();
          incr_second_key();
      }
      split_dec(ct_array, ct_len, 0+ext, ch, true);
      ext+=32;
      count++;
      }
      rest_k();
      rest_s_k();
      Serial.println(dec_st);
      dec_st = "";
    }
    if(x == 7)
      m = 0;
    if(x == 8)
      m = 1;
    if(x == 9)
      m = 2;
    if(x == 10){
      Serial.println("How many times do you want to increment the key?");
      while (!Serial.available()) {}
      int itr = Serial.parseInt();
      for(int i = 0; i < itr; i++){
        incr_key();
      }
    }
    if(x == 11){
     for(int cnt = 0; cnt < 16; cnt++){
      for (int i = 0; i < 32; ++i) {
        Serial.printf("%02x", gen_r_num());
      }
      Serial.println();
     }
    }
    if(x == 12){
      Serial.println("Enter the string to derive a part of the key from:");
      String input;
      while (!Serial.available()) {}
      input = Serial.readString();
      int str_len = input.length() + 1;
      char input_arr[str_len];
      input.toCharArray(input_arr, str_len);
      std::string str = "";
      if(str_len > 1){
        for(int i = 0; i<str_len-1; i++){
          str += input_arr[i];
        }
      }
      String h = sha512( str ).c_str();
      int h_len = h.length() + 1;
      char h_array[h_len];
      h.toCharArray(h_array, h_len);
      byte res[16] = {0};
      for (int i = 0; i < 32; i+=2){
      if (i == 0){
      if(h_array[i] != 0 && h_array[i+1] != 0)
      res[i] = 16*getNum(h_array[i])+getNum(h_array[i+1]);
      if(h_array[i] != 0 && h_array[i+1] == 0)
      res[i] = 16*getNum(h_array[i]);
      if(h_array[i] == 0 && h_array[i+1] != 0)
      res[i] = getNum(h_array[i+1]);
      if(h_array[i] == 0 && h_array[i+1] == 0)
      res[i] = 0;
      }
      else{
      if(h_array[i] != 0 && h_array[i+1] != 0)
      res[i/2] = 16*getNum(h_array[i])+getNum(h_array[i+1]);
      if(h_array[i] != 0 && h_array[i+1] == 0)
      res[i/2] = 16*getNum(h_array[i]);
      if(h_array[i] == 0 && h_array[i+1] != 0)
      res[i/2] = getNum(h_array[i+1]);
      if(h_array[i] == 0 && h_array[i+1] == 0)
      res[i/2] = 0;
      }
     }
     uint8_t ct1[32], pt1[32], key[64];
     int plen, clen, i, j;
     serpent_key skey;
     serpent_blk ct2;
     uint32_t *p;
     for (i=0; i<sizeof(keys)/sizeof(char*); i++) {
      hex2bin (key, keys[i]);
      memset (&skey, 0, sizeof (skey));
      p=(uint32_t*)&skey.x[0][0];
      serpent_setkey (&skey, key);
      for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
        if ((j % 8)==0) putchar('\n');
      }
      for(int i = 0; i <16; i++)
        ct2.b[i] = res[i];
      }
      for(int i = 0; i<576; i++)
        serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
      key[0] = ct2.b[0];
      key[1] = ct2.b[1];
      key[3] = ct2.b[2];
      key[4] = ct2.b[3];
      key[6] = ct2.b[4];
      key[7] = ct2.b[5];
      key[8] = ct2.b[12];
      second_key[0] = ct2.b[6];
      second_key[1] = ct2.b[7];
      second_key[3] = ct2.b[8];
      second_key[4] = ct2.b[9];
      second_key[6] = ct2.b[10];
      second_key[7] = ct2.b[11];
      second_key[8] = ct2.b[13];
      Serial.print("Key derived successfully. Verification number: ");
      Serial.println(ct2.b[14]);
    }
    if(x == 13){
     Serial.println("How many strings do you want?");
      while (!Serial.available()) {}
      int nmbr = Serial.parseInt();
      Serial.println("Random ASCII strings:");
      for(int sn = 0; sn < nmbr; sn++){
      int pt = 80 + gen_r_num();
      for(int i = 0; i < pt; i++){
        int r = gen_r_num();
        if(r>32 && r<127)
          Serial.print(char(r));
      }
      Serial.println();
      }
    }
    if(x == 14){
      Serial.print("Enter the data to hash:");
      String input;
      while (!Serial.available()) {}
      input = Serial.readString();
      Serial.println(input);
      int str_len = input.length() + 1;
      char input_arr[str_len];
      input.toCharArray(input_arr, str_len);
      std::string str = "";
      if(str_len > 1){
        for(int i = 0; i<str_len-1; i++){
          str += input_arr[i];
        }
      }
      String h = sha512( str ).c_str();
      Serial.println("Hash:");
      Serial.println(h);
    }
    if(x == 15){
      String cf;
      Serial.println("Enter the name of the new file");
      while (!Serial.available()) {}
      cf = Serial.readString();
      String cont;
      Serial.println("Enter the content of the new file");
      while (!Serial.available()) {}
      cont = Serial.readString();
      write_f("/" + cf, cont);
    }
    if(x == 16){
      String opn;
      Serial.println("Enter the name of the file to open");
      while (!Serial.available()) {}
      opn = Serial.readString();
      Serial.println(read_f("/" + opn));
    }
    if(x == 17){
      String rm;
      Serial.println("Enter the name of the file to delete");
      while (!Serial.available()) {}
      rm = Serial.readString();
      SPIFFS.remove("/" + rm);
    }
    if(x == 19){
      File root = SPIFFS.open("/");
      File file = root.openNextFile();
      while(file){
        Serial.print("FILE: ");
        Serial.println(file.name());
        file = root.openNextFile();
      }
    }
}
