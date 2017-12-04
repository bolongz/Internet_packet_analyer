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
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

std::string int_to_string(const int &a){
  //function for
  //std::cout << "your int " << a ;
  std::stringstream stream;
  stream << std::hex << a; //your_int;
  std::string result( stream.str());
  //std::cout << result << " " << result.size() <<  std::endl;
  return result;
}

void print_mac_address(uint8_t ad[6]){

   for(size_t i = 0 ; i< 6; i++){
     std::string d_mac;
     d_mac = int_to_string(int(ad[i]));
     if(i == 5) {
       std::cout << d_mac; //<< std::end;
       break;
     }
     std::cout << d_mac << ":";
   }
}

void print_protocol_address(uint8_t pd[4]){

  for(size_t i = 0; i < 4; i++){
    if(i == 3){
      std::cout << int(pd[i]) ; // << std::endl;
      break;
    }
    std::cout << int(pd[i]) <<".";
  }
}


std::string four_digit_hex(uint16_t type){ //print type
  //convert the uint16 to hex with length at least four
  std::string t = int_to_string(type);
  //std::cout << t << std::endl;
  if(t.size() == 3){
    t = "0" + t;
  }else if(t.size() == 2){
    t = "00" + t;
  }else if(t.size() == 1){
    t = "000" + t;
  }
  return t;
}

void print_hex(uint16_t type){ //print type
  std::string t = four_digit_hex(type);
  std::cout << t;
}

uint32_t nth_bit(uint32_t b, size_t n){
  return uint32_t(1) & (b >> n);
}// take the nth bit starting from 0


class Ethernet_frame{

private:

  uint8_t dest_mac[6]; //store the dest_address
  uint8_t src_mac[6]; //source mac
  uint16_t type; // frame type
  size_t packet_id; //packet_id;
  size_t packet_size; // packet size;
  std::string hex_type;
  //  Ethernet_frame();
public:

  void set_value(uint8_t d[6], uint8_t s[6], uint16_t tt,  size_t id, size_t ss){
    for(size_t i = 0; i  < 6; i++){
      dest_mac[i] = d[i];
      src_mac[i] = s[i];
    }
    type = tt;
    packet_id = id;
    packet_size = ss;
    hex_type = four_digit_hex(type);//value
  }
  bool is_boardcast(){
    bool _is_boardcast = true;
    for(size_t i = 0; i < 6; i++){
      if(size_t(dest_mac[i]) != 255) _is_boardcast = false;
    }
    return _is_boardcast;
  }
  size_t get_packet_size(){
    return packet_size;
  }

  std::string get_hex_type(){
    return hex_type;
  }
  void print_dest_mac(){ // print destination address
    print_mac_address(dest_mac);
  }
  void print_src_mac(){ //print srouce
    print_mac_address(src_mac);
  }
  void print_header(){ //print header
    std::cout << std::endl;
    std::cout << "ETHER:  " << "----- Ether Header -----" << std::endl;
    std::cout << "ETHER:" << std::endl;
    std::cout << "ETHER:  " << "Packet " << packet_id << std::endl;
    std::cout << "ETHER:  " << "Packet size = " << packet_size << " bytes" << std::endl;
    std::cout << "ETHER:  " << "Destination = ";
    print_dest_mac();
    std::cout << std::endl;
    std::cout << "ETHER:  " << "Source      = ";
    print_src_mac();
    std::cout << std::endl;

    std::cout << "ETHER:  " << "Ethertype   = " << hex_type; // << " ";
    if(hex_type == "0800"){
      std::cout << " (IP)" << std::endl;
    }else if(hex_type == "0806"){
      std::cout << " (ARP)" << std::endl;
    }else{
      std::cout << " (unknown)" << std::endl;
    }

    std::cout << "ETHER:" << std::endl;
  }
  void print_header_short(){

    if(hex_type != "0800" || hex_type != "0806"){
      std::cout << "unknow packet " <<"(";
      print_dest_mac();
      std::cout << ", " ;
      print_src_mac();
      std::cout <<", " <<hex_type << std::endl;
      std::cout << ")" <<std::endl;
    }
  }

};


class APR_Message{

private:

  uint16_t hardtype; // hard type
  uint16_t protocoltype; //protocol type

  uint8_t haddr_len; // hard address length
  uint8_t paddr_len; // protocol address length
  uint16_t operation; //operation
  uint8_t sender_haddr[6]; // sender hard address
  uint8_t sender_paddr[4]; // send protocol address
  uint8_t target_haddr[6]; // target hard addr
  uint8_t target_paddr[4]; // target protocol addr

  std::string hex_type;
public:

  void set_value(uint16_t ht, uint16_t pt, uint8_t hl, uint8_t pl, uint16_t op, uint8_t sh[6], uint8_t sp[4], uint8_t th[6], uint8_t tp[4]){

    hardtype = ntohs(ht);
    protocoltype = ntohs(pt);
    haddr_len = hl;
    paddr_len = pl;
    operation = ntohs(op);
    for(size_t i = 0; i < 6; i++){
      sender_haddr[i] = sh[i];
    }
    for(size_t i = 0; i < 4; i++){
      sender_paddr[i] = sp[i];
    }
    for(size_t i = 0; i < 6; i++){
      target_haddr[i] = th[i];
    }
    for(size_t i = 0; i < 4; i++){
      target_paddr[i] = tp[i];
    }
    hex_type = four_digit_hex(protocoltype);
  }
  void print_sender_haddr(){
    print_mac_address(sender_haddr);
  }
  void print_target_haddr(){
    print_mac_address(target_haddr);
  }
  bool is_unknown_address(){
    bool unknown = true;
    for(size_t i = 0 ; i< 6; i++){
     std::string d_mac;
     d_mac = int_to_string(int(target_haddr[i]));
     if(d_mac != "0") unknown = false;
    }
    return unknown;
  }

  void print_sender_paddr(){
    print_protocol_address(sender_paddr);
  }
  void print_target_paddr(){
    print_protocol_address(target_paddr);
  }

  void print_apr_message(){
    std::cout << "ARP:  ----- ARP Frame -----" << std::endl;
    std::cout << "ARP:  " << std::endl;
    std::cout << "ARP:  " << "Hardware type = " << int(hardtype);
    if(int(hardtype) == 1) std::cout << " (Ethernet)" << std::endl;
    std::cout << "ARP:  " << "Protocol type = " << hex_type ;
    if(hex_type == "0800"){
        std::cout << " (IP)" << std::endl;
    }else if(hex_type == "0806"){
      std::cout << " (ARP)" << std::endl;
    }else{
      std::cout << " (unknown)" << std::endl;
    }

    std::cout << "ARP:  " << "Length of hardware address = " <<int(haddr_len) <<" bytes"  << std::endl;
    std::cout << "ARP:  " << "Length of protocol address = " <<int(paddr_len) << " bytes" <<  std::endl;
    std::cout << "ARP:  " << "Opcode " << int(operation); // << std::endl;
    if(int(operation) == 1){
    std::cout << " (ARP Request)";
    }else if (int(operation) == 2){
      std::cout << " (ARP Reply)";
    }
    std::cout << std::endl;
    std::cout << "ARP:  Sender's hardware address = ";
    print_sender_haddr();
    std::cout << std::endl;
    std::cout << "ARP:  Sender's protocol address = ";
    print_sender_paddr();
    std::cout << std::endl;
    std::cout << "ARP:  Target hardware address = ";
    if(is_unknown_address()){
      std::cout << "?";
    }else{
      print_target_haddr();
    }
    std::cout << std::endl;
    std::cout << "ARP:  Target protocol address = ";
    print_target_paddr();
    std::cout << std::endl;
    std::cout << "ARP:" << std::endl;
  }
  void print_apr_message_short(){

    print_protocol_address(sender_paddr);
    std::cout << " -> ";
    print_protocol_address(target_paddr);
    std::cout << " ARP who is ";
    print_protocol_address(target_paddr);
    std::cout << std::endl;
  }
};

class ICMP{

private:
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t check_sum;
  uint16_t identifier;
  uint16_t squence_number;

public:

  void set_value(uint8_t it, uint8_t ic, uint16_t cs, uint16_t ii, uint16_t sn){
    icmp_type = it;
    icmp_code = ic;
    check_sum = ntohs(cs) ;
    identifier = ntohs(ii) ;
    squence_number = ntohs(sn);;
  }

  void print_icmp_type(){
    std::cout << int(icmp_type) << std::endl;
  }
  void print_icmp_code(){
    std::cout << int(icmp_code) << std::endl;
  }
  void print_check_sum(){
    std::cout << int(check_sum) << std::endl;
  }
  void print_identifier(){
    std::cout << int(identifier) << std::endl;
  }
  void print_squence_number(){
    std::cout << int(squence_number) << std::endl;
  }

  void print_icmp(){
    std::cout << "ICMP:  " << "----- ICMP Header -----" << std::endl;
    std::cout << "ICMP: " << std::endl;
    std::cout << "ICMP: " << "Type = " << int(icmp_type);
    if(int(icmp_type) == 0){
      std::cout<< " (Echo Reply)";
    }else if(int(icmp_type) == 8){
      std::cout<< " (Echo Request)";
    }std::cout<< std::endl;
    std::cout << "ICMP: " << "Code = " << int(icmp_code) << std::endl;
    std::string checksum = int_to_string(int(check_sum));
    std::cout << "ICMP: " << "Checksum = " << checksum << std::endl;
    std::cout << "ICMP: " << "Identifier = " << int(identifier) << std::endl;
    std::cout << "ICMP: " << "Sequence number = " << int(squence_number) << std::endl;
    std::cout << "ICMP:" << std::endl;
  }
};

class UDP{
  // UPD class provides some operations for UPD header
private:
  uint16_t source_port;
  uint16_t destination_port;
  uint16_t udp_length;
  uint16_t udp_checksum;

public:
  void set_value(uint16_t sp, uint16_t dp, uint16_t ul, uint16_t uc){
    source_port = ntohs(sp);
    destination_port = ntohs(dp);
    udp_length = ntohs(ul);
    udp_checksum = ntohs(uc);

  }

  void print_udp(){

    std::cout << "UDP:  " << "----- UDP Header -----" << std::endl;
    std::cout << "UDP: " << std::endl;
    std::cout << "UDP:  " << "Source port = " << int(source_port) << std::endl;
    std::cout << "UDP:  " << "Destination port = " << int(destination_port) << std::endl;
    std::cout << "UDP:  " << "Message length = " << int(udp_length) << std::endl;
    std::string checksum = int_to_string(int(udp_checksum));
    std::cout << "UDP:  " << "Checksum = " << checksum << std::endl;
    std::cout << "UDP:" << std::endl;
  }
};

class TCP{

private:

  uint16_t source_port;
  uint16_t destination_port;
  uint32_t sequence_number;
  uint32_t ack_number;
  uint8_t tcp_header_length;// store in the high 4 bits
  uint8_t flags;
  uint16_t window_size;
  uint16_t check_sum;
  uint16_t urgent_pointer;

public:
  void set_value(uint16_t sp, uint16_t dp, uint32_t sn, uint32_t an, uint8_t tl, uint8_t f, uint16_t ws, uint16_t cs, uint16_t up){
    source_port = ntohs(sp);
    destination_port = ntohs(dp);
    sequence_number = ntohl(sn);
    ack_number = ntohl(an);
    tcp_header_length = tl;
    flags = f;
    window_size = ntohs(ws);
    check_sum = ntohs(cs);
    urgent_pointer = ntohs(up);

  }

  void print_source_port(){
    std::cout << int(source_port) << std::endl;
  }
  void print_destination_port(){
    std::cout <<int(destination_port) << std::endl;
  }
  void print_sequence_number(){
    std::cout << size_t(sequence_number) << std::endl;
  }
  void print_ack_number(){
    std::cout << size_t(ack_number) << std::endl;
  }
  void print_flags(){

    for(size_t i = 0; i < 6; i++){
      size_t c = 0;
      std::cout << "TCP:      " ;
      for(size_t j = 0 ;j < i + 2; j++){
        if(j == 3){
          std::cout <<". ";

        }else{
          std::cout << ".";
        }
        c++;
      }
      uint32_t sign = nth_bit(flags, 5-i);
      if(c == 3){
        std::cout << nth_bit(flags, 5-i) << " " ;
      }else{
        std::cout << nth_bit(flags, 5-i);
      }
      // std::cout << c ;//<< std::endl;
      c++;
      for(size_t j = 0; j < 5-i; j++){
        if(c == 3){
          std::cout << ". " ;
        }else{
          std::cout <<".";
        }
        c++;

      }
      if(sign){
        if(i ==  0){
          std:: cout << " = " << "Urgent pointer";
        }else if(i == 1){
          std::cout<< " = " << "Acknowledgement";
        }else if(i == 2){
          std::cout << " = " << "Push" ;
        }else if(i == 3){
          std::cout <<" = " << "Reset";
        }else if(i == 4){
          std::cout << " = " << "Syn";
        }else if(i == 5){
          std::cout << " = " << "Fin";
        }
      }else{
        if(i ==  0){
          std:: cout << " = " << "No urgent pointer";
        }else if(i == 1){
          std::cout<< " = " << "No acknowledgement";
        }else if(i == 2){
          std::cout << " = " << "No push" ;
        }else if(i == 3){
          std::cout <<" = " << "No reset";
        }else if(i == 4){
          std::cout << " = " << "No Syn";
        }else if(i == 5){
          std::cout << " = " << "No Fin";
        }
      }
      std::cout << std::endl;
    }
  }
  void print_window_size(){
    print_hex(window_size);
  };
  void print_check_sum(){
    print_hex(check_sum);
  }
  void print_urgent_pointer(){
    std::cout << int(urgent_pointer) << std::endl;
  }
  void print_tcp(){

    std::cout << "TCP:  " << "----- TCP Header -----" << std::endl;
    std::cout << "TCP: " << std::endl;
    std::cout << "TCP:  " << "Source port = ";
    print_source_port();
    std::cout << "TCP:  " << "Destination port = ";
    print_destination_port();
    std::cout << "TCP:  " << "Sequence number = ";
    print_sequence_number();
    std::cout << "TCP:  " << "Acknowledgement number = ";
    print_ack_number();
    std::cout<< "TCP:  " << "Data offset = " << int(tcp_header_length) * 4 << " bytes" << std::endl;
    std::cout << "TCP:  Flags" << std::endl;
    print_flags();
    std::cout << "TCP:  " << "Window = " << int(window_size) << std::endl;
    std::cout << "TCP:  " << "Checksum = " << int_to_string(check_sum);
    //print_check_sum();
    std::cout << std::endl;
    std::cout << "TCP:  " << "Urgent pointer = ";
    print_urgent_pointer();
    if(int(tcp_header_length) * 4 > 20){
      std::cout << "TCP:  " << "Options ignored" << std::endl;
    }else{
      std::cout << "TCP:  " << "No options" << std::endl;
    }
    std::cout << "TCP:" << std::endl;

  }

};

class IP{

private:
  uint8_t ip_version;
  uint8_t header_length;
  uint8_t type_of_service;
  uint16_t total_length;
  uint16_t identification;
  uint16_t fragment_model; //one bit empty
  uint8_t time_to_live;
  uint8_t protocol;
  uint16_t check_sum;
  uint8_t source_address[4];
  uint8_t destination_address[4];

public:

  void set_value(uint8_t ip, uint8_t hl, uint8_t ts, uint16_t tl, uint16_t id, uint16_t fm, uint8_t tol, uint8_t pt, uint16_t cs, uint8_t sa[4], uint8_t da[4]){

    ip_version = ip;
    header_length = hl;
    type_of_service = ts;
    total_length = ntohs(tl);
    identification = ntohs(id);
    fragment_model = ntohs(fm);
    time_to_live = tol;
    protocol = pt;
    check_sum = ntohs(cs);
    for(size_t i = 0; i < 4; i++){
      source_address[i] = sa[i];
      destination_address[i] = da[i];
    }
  }
  int get_protocol(){
    return int(protocol);
  }
  void print_ip_version(){
    std::cout << int(ip_version) << std::endl;
  }

  void print_header_length(){
    std::cout << int(header_length) << std::endl;
  }
  void print_type_of_service(){
    std::cout << int(type_of_service) << std::endl;
  }
  void print_total_length(){
    std::cout << int(total_length) << std::endl;
  }
  void print_identification(){
    print_hex(identification);
    std::cout  << std::endl;
  }
  void print_flags(){
    uint32_t df  = nth_bit(fragment_model, 14);
    uint32_t mf  = nth_bit(fragment_model, 13);
    if(df == 0){
      std::cout << "IP:    ";
      std::cout << "." << "0.. .... = allow fragment" << std::endl;
    }else{
      std::cout << "IP:    ";
      std::cout << "." << "1.. .... = do not fragment" << std::endl;
    }
    if(mf == 0){
      std::cout << "IP:    ";
      std::cout << "." << ".0. .... = last fragment" << std::endl;
    }

  }
  void print_fragment_offset(){
    uint16_t fm = fragment_model & 0x1FFF;
    std::cout << int(fm) << " bytes" << std::endl;
  }
  void print_protocol(){
    std::cout << int(protocol); // << std::endl;
  }
  void print_check_sum(){
    print_hex(check_sum);
  }
  void print_source_address(){
    print_protocol_address(source_address);
  }
  void print_destination_address(){
    print_protocol_address(destination_address);
  }
  void print_ip(){

    std::cout << "IP:  " << "----- IP Header -----" << std::endl;
    std::cout << "IP:" << std::endl;
    std::cout << "IP:  " << "Version = ";
    print_ip_version();
    std::cout << "IP:  " << "Header length = " << int(header_length) * 4 << " bytes" << std::endl;;

    std::cout << "IP:  " << "Type of service = " << int_to_string(type_of_service) << std::endl;;
    std::cout << "IP:  " << "Total length = " << int(total_length) << " bytes"  << std::endl;
    std::cout << "IP:  " << "Identification = " << int(identification) << std::endl;;


    std::cout<< "IP:  " <<"Flags" << std::endl;;
    print_flags();
    std::cout << "IP:  " << "Fragment offset = ";
    print_fragment_offset();
    std::cout << "IP:  " << "Protocol = ";
    print_protocol();
    if(int(protocol) == 1){
      std::cout << " (ICMP)" << std::endl;
    }else if(int(protocol) == 17){
      std::cout << " (UDP)" << std::endl;
    }else if(int(protocol) == 6){
      std::cout << " (TCP)" << std::endl;
    }

    std::cout << "IP:  " << "Header checksum = " << int_to_string(check_sum) << std::endl;

    std::cout << "IP:  " << "Source address = ";
    print_source_address();
    std::cout <<std::endl;
    std::cout << "IP:  " << "Destination address = ";
    print_destination_address();
    std::cout << std::endl;

    if(int(header_length) > 20){
      std::cout << "IP:  " << "Options ignored" << std::endl;
    }else{
      std::cout << "IP:  " << "No options" << std::endl;
    }
    std::cout << "IP:" << std::endl;

  }


};


int main(int argc, char *argv[]){

  std::string filename(argv[1]); // input the dumpfile
  std::string print_command = "s"; //default value //(argv[2]);
  int lines_number = -1;

  if(argc > 2){
    std::string lines(argv[2]);
    if(lines == "-c"){
      lines_number = atoi(argv[2]);
    }else{

      if(lines == "-v"){
        print_command = "a"; // print address;
      }else if (lines == "-V"){
        print_command = "d"; // print details
      }
    }
  }

  FILE *fileptr = fopen(filename.c_str(), "rb"); //open the input file;
  if( fileptr == NULL) std::cout <<"Open file failed!" << std::endl;
  fseek(fileptr, 0, SEEK_END); //calcutate the length of the file
  size_t filelen = ftell(fileptr);

  //  FILE *outptr =fopen("decoded_output2", "w+");
  rewind(fileptr);
  /* ---- counter init ------ */
  size_t process_length  = 0;
  size_t ethernet_frame_count = 0;
  size_t ethernet_boardcast = 0;
  size_t apr_packets = 0;
  size_t ip_packets =0;
  size_t udp_packets = 0;
  size_t tcp_packets = 0;
  size_t icmp_packets = 0;
  size_t other_ip_packets = 0;
  size_t other_packets;
  size_t packet_id = 0;
  /* ---- counter init end ----*/
  while(process_length < filelen){

    uint32_t frame_length = 0;
    size_t read_length = 0;
    fread(&frame_length, 4, 1, fileptr); process_length += 4; // read the length of the frame with the first 4 bytes
    ethernet_frame_count++;
    if(lines_number != -1 && ethernet_frame_count > size_t(lines_number)) break;
    read_length = 4;
    packet_id++;

    frame_length = ntohl(frame_length); //convert the order to local host order

    //    std::cout << "id " << packet_id << "  ethernet_frame_count " << ethernet_frame_count << " frame length:  " << frame_length  << "  " << process_length << " " << filelen <<   std::endl;
    /* ---------- Reading Ethernet Frame ------------ */
    Ethernet_frame ethernet_frame;
      //first 6 bytes: destination address
    uint8_t dest[6];
    fread(dest, 1, 6, fileptr); // read the destination address
    uint8_t src[6];
    fread(src, 1, 6, fileptr); // read the srouce address
    uint16_t type;
    fread(&type, 2, 1, fileptr); // read the type
    type = ntohs(type);
    read_length += 14; // add 14 bytes
    ethernet_frame.set_value(dest, src, type, packet_id - 1, frame_length);
    if(ethernet_frame.is_boardcast()) ethernet_boardcast++; // count the boardcasting
    if(print_command == "d"){
      ethernet_frame.print_header(); // print the header for the ethernet frame
    }else if(print_command == "a"){
      ethernet_frame.print_header_short();
    }
    /* ---------- END Reading Ethernet Frame ------------ */
    /* ---------- Reading APR Frame ------------ */
    if(ethernet_frame.get_hex_type() == "0806"){
      //APR message : start reading APR header
      APR_Message apr_message;
      uint16_t hard_type; // read hard address type
      fread(&hard_type, 2, 1, fileptr);
      uint16_t protocol_type;
      fread(&protocol_type, 2, 1, fileptr);
      uint8_t haddr_len;
      fread(&haddr_len, 1, 1, fileptr);
      uint8_t paddr_len;
      fread(&paddr_len, 1, 1, fileptr);
      uint16_t operation;
      fread(&operation, 2, 1, fileptr);
      uint8_t sender_haddr[6];
      fread(sender_haddr, 1, 6, fileptr);
      uint8_t sender_paddr[4];
      fread(sender_paddr, 1, 4, fileptr);
      uint8_t target_haddr[6];
      fread(target_haddr, 1, 6, fileptr);
      uint8_t target_paddr[4];
      fread(target_paddr, 1, 4, fileptr);
      apr_packets++;
      apr_message.set_value(hard_type, protocol_type, haddr_len, paddr_len, operation, sender_haddr, sender_paddr, target_haddr, target_paddr);
      read_length += 28;
      if(print_command == "d"){
        apr_message.print_apr_message();
      }else if(print_command == "a"){
        apr_message.print_apr_message_short();
      }
      /* ---------- END APR Frame ------------ */
      /* ----------  Reading IP  Frame ------------ */
    }else if(ethernet_frame.get_hex_type() == "0800") {
      //IP message
      IP ip_frame;
      uint8_t ip_hl;
      fread(&ip_hl, 1, 1, fileptr);
      uint8_t ip_version = (ip_hl & 0xF0) >> 4;
      uint8_t header_length = ip_hl & 0x0F;
      uint8_t type_of_service;
      fread(&type_of_service, 1, 1, fileptr);

      uint16_t total_length;
      fread(&total_length, 2, 1, fileptr);
      uint16_t identification;
      fread(&identification, 2, 1, fileptr);
      uint16_t fragment_model;
      fread(&fragment_model, 2, 1, fileptr);
      uint8_t time_to_live;
      fread(&time_to_live, 1, 1, fileptr);
      uint8_t protocol;
      fread(&protocol, 1, 1, fileptr);
      uint16_t checksum;
      fread(&checksum, 2, 1, fileptr);
      uint8_t source_address[4];
      fread(&source_address, 1, 4, fileptr);
      uint8_t destination_address[4];
      fread(&destination_address, 1, 4, fileptr);
      ip_packets++;
      ip_frame.set_value(ip_version, header_length, type_of_service, total_length, identification, fragment_model, time_to_live, protocol, checksum, source_address, destination_address);

      read_length += int(header_length);
      if(print_command == "d"){
        ip_frame.print_ip();
      }
      /* ------- ICMP starting reading ------- */
      if(ip_frame.get_protocol() == 1){

        ICMP icmp_frame; // icmp frame
        uint8_t icmp_type;

        fread(&icmp_type, 1, 1, fileptr);
        uint8_t icmp_code;
        fread(&icmp_code, 1, 1, fileptr);
        uint16_t check_sum;
        fread(&check_sum, 2, 1, fileptr);
        uint16_t identifier;
        fread(&identifier, 2, 1, fileptr);
        uint16_t squence_number;
        fread(&squence_number, 2, 1, fileptr);
        read_length += 8;
        icmp_frame.set_value(icmp_type, icmp_code, check_sum, identifier, squence_number);
        icmp_packets++;
        if(print_command == "d"){
          icmp_frame.print_icmp();
        }
      /* ------- END ICMP reading ------- */
        /* ------- UDP starting reading ------- */
      }else if( ip_frame.get_protocol() == 17){
        UDP udp_frame;
        uint16_t source_port;
        fread(&source_port, 2, 1, fileptr);
        uint16_t destination_port;
        fread(&destination_port, 2, 1, fileptr);
        uint16_t udp_length;
        fread(&udp_length, 2, 1, fileptr);
        uint16_t udp_checksum;
        fread(&udp_checksum, 2, 1, fileptr);
        read_length += 8;
        udp_frame.set_value(source_port, destination_port, udp_length, udp_checksum);
        if(print_command == "d"){
          udp_frame.print_udp();
        }
        udp_packets++;
        /* ------- END UDP reading ------- */
        /* ------- TCP reading ------- */
      }else if(ip_frame.get_protocol() == 6){
        //  std::cout << " HERE TCP " << std::endl;
        TCP tcp_frame;
        uint16_t source_port;
        fread(&source_port, 2, 1, fileptr);
        uint16_t destination_port;
        fread(&destination_port, 2, 1, fileptr);
        uint32_t sequence_number;
        fread(&sequence_number, 4, 1, fileptr);
        uint32_t ack_number;
        fread(&ack_number, 4, 1, fileptr);
        uint8_t tcp_header_length;// store in the high 4 bits

        fread(&tcp_header_length, 1, 1, fileptr);
        tcp_header_length = tcp_header_length >> 4;
        uint8_t flags;
        fread(&flags, 1, 1, fileptr);
        uint16_t window_size;
        fread(&window_size, 2, 1, fileptr);
        uint16_t check_sum;
        fread(&check_sum, 2, 1, fileptr);
        uint16_t urgent_pointer;
        fread(&urgent_pointer, 2, 1, fileptr);
        tcp_frame.set_value(source_port, destination_port, sequence_number, ack_number, tcp_header_length, flags, window_size, check_sum, urgent_pointer);
        read_length += int(tcp_header_length);
        if(print_command == "d"){
          tcp_frame.print_tcp();
        }

        // if(int(tcp_header_length) > 20){
        //   fseek(fileptr, int(tcp_header_length) -20, SEEK_CUR);
        // }
        tcp_packets++;

      }else{
        other_ip_packets++;
      }
      /* ------- END TCP reading ------- */

      /* ----------  END Reading IP  Frame ------------ */
    }else{

      other_packets++;
    }
    // if(ethernet_frame.get_packet_size() - read_length > 0){
    //   fseek(fileptr, ethernet_frame.get_packet_size() - read_length, SEEK_CUR);
    // }
    rewind(fileptr);

    process_length += ethernet_frame.get_packet_size();
    fseek(fileptr, process_length, SEEK_SET);
    //  std::cout << "AFTER loop " << process_length  << " " << ethernet_frame.get_packet_size() << std::endl;

  }
  if(print_command == "s"){

    std::cout << "Ethernet frames:        " << ethernet_frame_count << std::endl;
    std::cout << "Ethernet broadcast:     " <<ethernet_boardcast << std::endl;
    std::cout << "  ARP packets:          " << apr_packets << std::endl;
    std::cout << "  IP packets:           " << ip_packets << std::endl;
    std::cout << "    UDP packets:        " << udp_packets << std::endl;
    std::cout << "    TCP packets:        " << tcp_packets << std::endl;
    std::cout << "    ICMP packets:       " << icmp_packets << std::endl;
    std::cout << "    other IP packets:   " << other_ip_packets << std::endl;
    std::cout << "  other packets:        " << other_packets++ << std::endl;
  }

  //}
  return 0;
}
