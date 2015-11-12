#include "network_tool.h"

int main(void)
{
	int err;
	network_info net;

	err = get_network_info(&net);
	if(err < 0)
		printf("get network info error\n");
	else
	{
		printf("ipaddr: %s\n", net.ipaddr);
		printf("netmask: %s\n", net.netmask);
		printf("gateway: %s\n", net.gateway);
	}
	
}

