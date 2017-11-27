//Project 4 for Data Comm
//author: Bolong Zhang
//Data: 11/27/2017
//FSUID: bz15
//CSID: bzhang
#include<iostream>
#include<vector>
#include<string>
#include "stdlib.h"
#include "stdio.h"


int main(int argc, char *argv[]){

  std::string filename(argv[1]); // input the dumpfile
  std::string command = "S"; //default value //(argv[2]);
  if(argc > 1){
    std::string method(argv[2]);
    command = method; // input the parameters for the program
  }

  FILE *fileptr = fopen(fileptr.c_str(), "rb"); //open the input file;
  if( fileptr == NULL) std::cout <<"Open file failed!" << std::endl;
  fseek(fileptr, 0, SEEK_END); //calcutate the length of the file
  size_t filelen = ftell(fileptr);

  //  FILE *outptr =fopen("decoded_output2", "w+");
  rewind(fileptr);
  size_t process_length  = 0;
  while(process_length < filelen){
    uint32_t frame_length = 0;
    fread(&frame_length, 4, 1, fileptr); process_length += 4; // read the length of the frame with the first 4 bytes
    frame_length = ntohl(frame_length); //convert the order to local host order
  }
  return 0;

}
