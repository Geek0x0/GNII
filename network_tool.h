#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>

uint8_t DEVICE_TYPE = 1;

#define BUFSIZE 8192

typedef struct {
	char ipaddr[255];
	char netmask[255];
	char gateway[255];
} network_info;

struct route_info {
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};

static inline int
readNlSock(int sockFd, char *bufPtr, int seqNum, int pId)
{
	struct nlmsghdr *nlHdr;
	int readLen = 0, msgLen = 0;

	do 
	{
		/* Recieve response from the kernel */
		if ((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0) 
		{
			perror("SOCK READ: ");
			return -1;
		}

		nlHdr = (struct nlmsghdr *) bufPtr;

		/* Check if the header is valid */
		if ((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR)) 
		{
			perror("Error in recieved packet");
			return -1;
		}

		/* Check if the its the last message */
		if (nlHdr->nlmsg_type == NLMSG_DONE) 
		{
			break;
		} 
		else 
		{
			/* Else move the pointer to buffer appropriately */
			bufPtr += readLen;
			msgLen += readLen;
		}

		/* Check if its a multi part message */
		if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) 
		{
			/* return if its not */
			break;
		}
	}while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));
	return msgLen;
}

/* For parsing the route info returned */
inline void 
parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo, char *gateway)
{
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen;

    rtMsg = (struct rtmsg *) NLMSG_DATA(nlHdr);

    if ((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
        return;

    rtAttr = (struct rtattr *) RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) 
	{
        switch (rtAttr->rta_type) 
		{
	        case RTA_OIF:
	            if_indextoname(*(int *) RTA_DATA(rtAttr), rtInfo->ifName);
	            break;
	        case RTA_GATEWAY:
	            rtInfo->gateWay.s_addr= *(u_int *) RTA_DATA(rtAttr);
	            break;
	        case RTA_PREFSRC:
	            rtInfo->srcAddr.s_addr= *(u_int *) RTA_DATA(rtAttr);
	            break;
	        case RTA_DST:
	            rtInfo->dstAddr .s_addr= *(u_int *) RTA_DATA(rtAttr);
	            break;
        }
    }

    if (rtInfo->dstAddr.s_addr == 0)
        sprintf(gateway, (char *) inet_ntoa(rtInfo->gateWay));
	
    return;
}


static inline int 
get_gateway(char *gateway)
{
    struct nlmsghdr *nlMsg;
    struct rtmsg *rtMsg;
    struct route_info *rtInfo;
    char msgBuf[BUFSIZE];

    int sock, len, msgSeq = 0;

/* Create Socket */
    if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
    {
        perror("Socket Creation: ");
		return -1;
    }

    memset(msgBuf, 0, BUFSIZE);

/* point the header and the msg structure pointers into the buffer */
    nlMsg = (struct nlmsghdr *) msgBuf;
    rtMsg = (struct rtmsg *) NLMSG_DATA(nlMsg);

/* Fill in the nlmsg header*/
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));	// Length of message.
    nlMsg->nlmsg_type = RTM_GETROUTE;   					// Get the routes from kernel routing table .

    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;    	// The message is a request for dump.
    nlMsg->nlmsg_seq = msgSeq++;    						// Sequence of the message packet.
    nlMsg->nlmsg_pid = getpid();    						// PID of process sending the request.

/* Send the request */
    if (send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0) 
	{
        printf("Write To Socket Failed...\n");
        return -1;
    }

/* Read the response */
    if ((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0) 
	{
        printf("Read From Socket Failed...\n");
    	return -1;
    }
/* Parse and print the response */
    rtInfo = (struct route_info *) malloc(sizeof(struct route_info));
    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) 
	{
        memset(rtInfo, 0, sizeof(struct route_info));
        parseRoutes(nlMsg, rtInfo, gateway);
    }
	
    free(rtInfo);
    close(sock);

    return 0;
}

static inline int 
get_network_info(network_info *net)
{
	int fd;
	struct ifreq ifr;
	char *iface = NULL;

	if(!net)
		return -1;
	memset(net, 0, sizeof(network_info));

	switch(DEVICE_TYPE)
	{
		case 1:
			iface = "eth0";
		break;
		case 2:
			iface = "eth1";
		break;
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
	{
		printf("create socket error\n");
		return -1;
	}
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ - 1);

	//get the ip address
	ioctl(fd, SIOCGIFADDR, &ifr);
	strcpy(net->ipaddr, 
		inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr));
	//get the netmask ip
	ioctl(fd, SIOCGIFNETMASK, &ifr);
	strcpy(net->netmask, 
		inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr));
	close(fd);

	if(get_gateway(net->gateway) < 0 )
		return -1;

	return 0;
}
