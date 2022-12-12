#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stddef.h>

int main(int argc, char **argv) {
	struct ifreq *ifr = NULL;

	(void) argc;
	(void) argv;
	(void) ifr;

	printf("TUNSETIFF=%lu\n", TUNSETIFF);
	printf("IFNAMSIZ=%u\n", IFNAMSIZ);
	printf("IFF_TAP=%u\n", IFF_TAP);
	printf("IFF_TUN=%u\n", IFF_TUN);
	printf("IFF_NO_PI=%u\n", IFF_NO_PI);
	printf("size_struct_ifreq=%zu\n", sizeof(struct ifreq));
	printf("offset_ifreq_ifr_flags=%zu\n", offsetof(struct ifreq, ifr_flags));
	printf("size_ifreq_ifr_flags=%zu\n", sizeof(ifr->ifr_flags));
	return 0;
}
