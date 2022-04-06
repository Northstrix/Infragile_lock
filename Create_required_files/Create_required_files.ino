/*
Infragile lock
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://github.com/Northstrix/Infragile_lock
*/
#include "SPIFFS.h"
String chck;
void read_f(String name){
  File file = SPIFFS.open(name);
  if(!file){
    Serial.println("Failed to open file for reading");
    return;
  }
  while(file.available()){
    chck += char(file.read());
  }
  file.close();
}

void write_f(String name, String cont){
  File file = SPIFFS.open(name, FILE_WRITE);
 
  if (!file) {
    Serial.println("There was an error opening the file for writing");
    return;
  }
  if (file.print(cont)) {
    Serial.println("File was written");
  } else {
    Serial.println("File write failed");
  }
 
  file.close();
}
void setup() {
  Serial.begin(115200);
  if (!SPIFFS.begin(true)) {
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }
  
  write_f("/a", "31");
  write_f("/b", "31");
  write_f("/c", "31");
  write_f("/d", "31");
  write_f("/e", "31");
  write_f("/f", "31");
  write_f("/g", "31");
  write_f("/j", "31");
  write_f("/k", "31");
  write_f("/l", "31");
  
  for (int i = 0; i < 10; i++){
    write_f("/" + String(i), "0");
  }
  read_f("/a");
  read_f("/b");
  read_f("/c");
  read_f("/d");
  read_f("/e");
  read_f("/f");
  read_f("/g");
  read_f("/j");
  read_f("/k");
  read_f("/l");
  
  for (int i = 0; i < 10; i++){
    read_f("/" + String(i));
  }

  if (chck == "313131313131313131310000000000"){
    Serial.println("Setup completed successfully!");
  }
  else {
    Serial.println("Setup has failed!");
  }
}

void loop() {
  // put your main code here, to run repeatedly:

}
