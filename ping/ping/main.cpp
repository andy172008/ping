//
//  main.cpp
//  ping
//
//  Created by System Administrator on 2018/11/22.
//  Copyright © 2018年 贺星宇. All rights reserved.
//

#include <iostream>
using namespace std;
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sstream>

#define BUFSIZE 1500

//为了在输出时能找到名字
char dest_name[100];
//记录当前时间
timeval tvnow;
//套接字描述符
int sockfd = 0;
//ipv4套接字地址结构
sockaddr_in dest_addr;
//数据部分长度
int datalen = 56;
//icmp包
char sendbuf[BUFSIZE];
//接收包
char recvbuf[BUFSIZE];

uint16_t GetCksum(uint16_t *addr, int len);
void SendPacket(int sendcount);
void RecvePacket();
int unpack(int recvlen);

int main(int argc, const char * argv[]) {
    
    //检查输入的格式是否正确
    if(argc != 6 || strcmp(argv[2],"-l") != 0 || strcmp(argv[4],"-n") != 0){
        perror("please enter the correct format\n");
        return 0;
    }
    
    
    
    sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(sockfd < 0){
        perror("create socket error\n");
        return 0;
    }
    
    //将用户输入的参数转换为网络字节序
    in_addr_t inaddr = 0;
    
    inaddr = inet_addr(argv[1]);
    
    //此时说明用户输入的是域名
    if(inaddr == INADDR_NONE){
        hostent* host = NULL;
        host = gethostbyname(argv[1]);
        if(host == NULL){
            perror("host name error\n");
            return 0;
        }
        memmove(&dest_addr.sin_addr.s_addr,host->h_addr_list[0],host->h_length);
    }
    //此时说明用户输入的是ip地址，已经成功被转换为网络字节序
    else{
        dest_addr.sin_addr.s_addr = inaddr;
    }
    
    //储存目标的名字
    strcpy(dest_name,argv[1]);
    
    //发送包的个数
    int pkcount = 0;
    
    stringstream ss;
    
    //读入发包数量
    ss << argv[5];
    ss >> pkcount;
    ss.clear();
    
    //读入数据大小
    ss << argv[3];
    ss >> datalen;
    
    //当前发送包的编号
    int sendcount = 1;
    
    
    
    while(sendcount <= pkcount){
        SendPacket(sendcount);
        RecvePacket();
        sendcount++;
        
    }
    
    
    
    
    return 0;
}

//发送包
void SendPacket(int sendcount){
    int len = 0;
    icmp *icmppacket;
    icmppacket = (icmp*) sendbuf;
    icmppacket->icmp_type = ICMP_ECHO;
    icmppacket->icmp_code = 0;
    icmppacket->icmp_cksum = 0;
    icmppacket->icmp_id = getpid();
    icmppacket->icmp_seq = sendcount;
    memset(icmppacket->icmp_data,0xa5,datalen);
    gettimeofday((timeval*)icmppacket->icmp_data,NULL);
    
    
    //这里的报头分为两个部分，一部分是8字节的固定报头，一部分是16字节的时间戳
    len = 8 + sizeof(timeval)+datalen;
    icmppacket->icmp_cksum = GetCksum((uint16_t*)icmppacket, len);
    
    sendto(sockfd, sendbuf, len, 0, (sockaddr *)&dest_addr, sizeof(sockaddr_in));
}



//计算校验和
uint16_t GetCksum(uint16_t *addr, int len){
    int nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;
    
    
    while(nleft > 1){
        sum += *w;
        w++;
        nleft -= 2;
    }
    
    if(nleft == 1){
        *(unsigned char*)(&answer) = *(unsigned char*) w;
        sum += answer;
    }
    
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

//接收包
void RecvePacket(){
    int recvlen = 0;
    socklen_t addrlen = 0;
    
    addrlen = sizeof(sockaddr_in);
    
    
    
    
    while(1){
        //设置时间限制，一秒未收到，则跳出
        timeval tv_out;
        tv_out.tv_sec = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));
        //获取返还的包
        recvlen = recvfrom(sockfd, recvbuf, BUFSIZ, 0, (sockaddr *)&dest_addr , &addrlen);
        gettimeofday(&tvnow, NULL);
        if(recvlen < 0)
        {
            printf("Request timeout for %s\n",dest_name);
            return ;
        }
        
        //解包，并进行统计
        int unpackflag = 0;
        
        unpackflag = unpack(recvlen);
        if(unpackflag == 1){
            break;
        }
        cout<<""<<endl;
    }
    
    //暂停一秒
    sleep(1);
    
}

//解包
int unpack(int recvlen){
    ip *ipH;
    icmp *icmpH;
    timeval *tvsend;
    
    //ip报头长度
    int ipheadlen = 0;
    
    
    ipH = (ip *)recvbuf;
    //获得ip报头的长度
    ipheadlen = ipH->ip_hl << 2;
    
    icmpH = (icmp *)(recvbuf + ipheadlen);
    
    //此时说明是畸形包
    if(recvlen - ipheadlen < 8){
        return 0;
    }
    
    //检验是否是发出包的回应
    if(icmpH->icmp_type == ICMP_ECHOREPLY){
        if(icmpH->icmp_id != getpid()){
            return 0;
        }
        if(recvlen - ipheadlen < 24){
            return 0;
        }
        
        //计算时间差
        tvsend = (timeval *)icmpH->icmp_data;
        
        
        tvnow.tv_sec -= tvsend->tv_sec;
        tvnow.tv_usec -= tvsend->tv_usec;
        
        double rtt = 0;
        rtt = tvnow.tv_sec * 1000 + tvnow.tv_usec / 1000.0;
        
        printf("%d bytes from %s:time = %f\n",datalen,dest_name,rtt);
        //cout <<"time:"<< rtt<<endl;
        return 1;
        
    }
    
    return 0;
}
