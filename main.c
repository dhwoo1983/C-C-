

#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>


std::string FnGet_SourceIP()
{
   
    char myip[20];
    
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    const char* kGoogleDnsIp = "8.8.8.8";
    int kDnsPort = 53;
        
    struct sockaddr_in serv;
    struct sockaddr_in host_name;           

    memset(&serv, 0, sizeof(serv));

    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons(kDnsPort);

    if( connect(sockfd, (struct sockaddr *)&serv, sizeof(serv)) < 0 ) 
    {
        return "-1";
    }
    socklen_t host_len = sizeof(host_name);
    if( getsockname(sockfd, (struct sockaddr *)&host_name, &host_len) < 0 ) 
    {
        return "-1";
    }
        
        
    inet_ntop(AF_INET, &host_name.sin_addr, myip, sizeof(myip));
    close(sockfd);

    std::string ret_IP(myip);
    return ret_IP;
}

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
    register long sum;
    u_short oddbyte;
    register u_short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return (answer);
}

 
int main()
{
    char host_addr[64];
    std::string str_HostIP;
    str_HostIP = FnGet_SourceIP();
    if( str_HostIP == "-1")
    {
        return 0;
    }
    
    strcpy(host_addr, str_HostIP.c_str());

    char serv_addr[64];
    memset( serv_addr, 0x00, sizeof(serv_addr) );
    //serv_addr='X.X.X.X';
    //FDK_Config_Get_Host_IP(serv_addr, sizeof(serv_addr) /* upto 16byte*/);
    
    if(serv_addr==NULL)
    {
        return 0;
    }

    unsigned long source_addr;
    unsigned long dest_addr;
    
    int payload_size = 64, sent = 0, sent_size;

    source_addr = inet_addr(host_addr);
    dest_addr = inet_addr(serv_addr);

    int sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (sockfd < 0) 
    {
       return (0);
    }
    
    int on = 1;

    // We shall provide IP headers
    if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) 
    {
        return (0);
    }
    //allow socket to send datagrams to broadcast addresses
    if (setsockopt (sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof (on)) == -1) 
    {
        return (0);
    }	
    //Calculate total packet size
    int packet_size = sizeof (struct iphdr) + sizeof (struct icmphdr) + payload_size;
    char *packet = (char *) malloc (packet_size);
                
    if (!packet) 
    {
        close(sockfd);
        return (0);
    }

    //ip header
    struct iphdr *ip = (struct iphdr *) packet;
    struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));

    //zero out the packet buffer
    memset (packet, 0, packet_size);

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons (packet_size);
    ip->id = rand ();
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = source_addr;
    ip->daddr = dest_addr;
    
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.sequence = rand();
    icmp->un.echo.id = rand();
    //checksum
    icmp->checksum = 0;

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = dest_addr;
    memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
    
    
    while (sent < 5) //while (1)
    {
        memset(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), rand() % 255, payload_size);
        
        //recalculate the icmp header checksum since we are filling the payload with random characters everytime
        icmp->checksum = 0;
        icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + payload_size);
        
        if ( (sent_size = sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
        {
            break;
        }
        ++sent;
        fflush(stdout);
        
        usleep(10000);	//microseconds
    }

    free(packet);
    close(sockfd);

    return 0;
}

