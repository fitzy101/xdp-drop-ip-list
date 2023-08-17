#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include "xdp-drop-ip-list.h"

#define DEBUG_LINE(line) (printf("got here %i\n", line))

struct xdp_program *prog = NULL;
static int ifindex = -1;

int detach_prog() {
    int ret = xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
    if (ret != 0) {
        fprintf(stderr, "Failed to detach XDP program from interface, got error %s\n", strerror(ret));
    } else {
        fprintf(stdout, "Detached XDP program\n");
    }
    return ret;
}

void close_prog() {
    xdp_program__close(prog);
}

// print statistics for packets dropped per target
static void poll_stats(int map_fd, int interval) {
    for (;;) {
        sleep(interval);
        struct target_key key;
        memset(&key, 0, sizeof(key));  /* clears value from previous iteration */
        while (bpf_map_get_next_key(map_fd, &key, &key) == 0) {
            long value = 0;
            bpf_map_lookup_elem(map_fd, &key, &value);

            char address_human[INET6_ADDRSTRLEN] = { 0 };
            struct in_addr addr_in = {
                .s_addr = 0,
            };
            struct in6_addr addr_in6 = {
                .s6_addr32 = { 0 },
            };

            switch (key.addr_family) {
                case AF_INET:
                    addr_in.s_addr = key.srcip[0];
                    if (inet_ntop(AF_INET, &addr_in, address_human, INET_ADDRSTRLEN) == NULL) {
                        printf("error converting address to human readable format\n");
                    }
                    break;
                case AF_INET6:
                    memcpy(&addr_in6.s6_addr32, &key.srcip, sizeof(key.srcip));
                    if (inet_ntop(AF_INET6, &addr_in6, address_human, INET6_ADDRSTRLEN) == NULL) {
                        printf("error converting address to human readable format\n");
                    }
                    break;
            }

            printf("total dropped for %s: %li\n", address_human, value);
        }
    }
}

int read_address_file(const char *filepath, char ***dest) {
    FILE *f;
    f = fopen(filepath, "r");
    if (f == NULL) {
        fprintf(stderr, "failed to open %s\n", filepath);
        return -1;
    }

    int curr_line = 0;
    size_t len = 0;
    ssize_t nread;
    char *line = NULL;
    char **address_list = NULL;
    while ((nread = getline(&line, &len, f)) != -1) {
        address_list = realloc(address_list, sizeof(char *) * (curr_line+1));
        address_list[curr_line] = strndup(line, nread-1);  /* don't include the newline */
        curr_line += 1;
    }
    fclose(f);

    *dest = address_list;
    return curr_line;
}

int populate_targets(int map_fd, const char ***addresses, const int address_count) {
    bool drop = true;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_protocol = IPPROTO_TCP;

    const char **address_list = *addresses;

    for (int i = 0; i < address_count; i++) {
        struct addrinfo *result, *rp;
        int s = getaddrinfo(address_list[i], NULL, &hints, &result);
        if (s != 0) {
            fprintf(stderr, "getaddrinfo: failed for %s: %s\n",
                    address_list[i],
                    gai_strerror(s));
            continue;
        }

        for (rp = result; rp != NULL; rp = rp->ai_next) {
            char address_human[INET6_ADDRSTRLEN] = { 0 };
            struct sockaddr_in* addr_in = NULL;
            struct sockaddr_in6* addr_in6 = NULL;
            struct target_key key;
            memset(&key, 0, sizeof(key));

            switch (rp->ai_family) {
                case AF_INET:
                    addr_in = (struct sockaddr_in*) rp->ai_addr;
                    if (inet_ntop(rp->ai_family, &(addr_in->sin_addr), address_human, INET_ADDRSTRLEN) == NULL) {
                        fprintf(stderr, "failed to convert address to string\n");
                        continue;
                    }

                    key.addr_family = AF_INET;
                    key.srcip[0] = addr_in->sin_addr.s_addr;
                    break;

                case AF_INET6:
                    addr_in6 = (struct sockaddr_in6*) rp->ai_addr;
                    if (inet_ntop(rp->ai_family, &(addr_in6->sin6_addr), address_human, INET6_ADDRSTRLEN) == NULL) {
                        fprintf(stderr, "failed to convert address to string\n");
                        continue;
                    }

                    key.addr_family = AF_INET6;
                    memcpy(&key.srcip, &addr_in6->sin6_addr.s6_addr32, sizeof(key.srcip));
                    break;

                default:
                    /* invalid address */
                    continue;
            }

            fprintf(stdout, "blocking address: %s\n", address_human);
            bpf_map_update_elem(map_fd, &key, &drop, BPF_NOEXIST);
        }
    }

    return 0;
}

// must_getenv is guaranteed to return a non-NULL value. Exits immediately with
// an error if the environment variable is not present.
const char *must_getenv(const char *name) {
	const char *value = getenv(name);
	if (value == NULL) {
		fprintf(stderr, "%s must be present in the environment\n", name);
		exit(EXIT_FAILURE);
	}
	return value;
}

static void int_exit(int sig) {
    int status = detach_prog();
    close_prog();
    exit(status == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    const char *address_file_path = must_getenv("XDP_DROP_ADDRESS_LIST_FILEPATH");
    const char *if_name = must_getenv("XDP_DROP_INTERFACE_NAME");
    const char *program_filepath = must_getenv("XDP_DROP_PROGRAM_FILEPATH");
    static const char *section_name = "xdp_drop";

    prog = xdp_program__open_file(program_filepath, section_name, NULL);
    if (!prog) {
        fprintf(stderr, "Failed to load BPF object file at %s\n", program_filepath);
        return EXIT_FAILURE;
    }

    ifindex = if_nametoindex(if_name);
    if (ifindex == -1) {
        printf("Invalid interface specified in XDP_DROP_INTERFACE_NAME: %s\n", if_name);
        return EXIT_FAILURE;
    }

    int ret = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0);
    if (ret != 0) {
        fprintf(stderr, "Failed to attach XDP program to interface %s, got error %s\n", if_name, strerror(ret));
        close_prog();
        return EXIT_FAILURE;
    }

    struct bpf_object *bpf_obj = xdp_program__bpf_obj(prog);
    int dropped_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "dropped");
    if (dropped_map_fd < 0) {
        fprintf(stderr, "finding dropped map from BPF program failed\n");
        detach_prog();
        close_prog();
        return EXIT_FAILURE;
    }

    int targets_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "targets");
    if (targets_map_fd < 0) {
        fprintf(stderr, "finding target map from BPF program failed\n");
        detach_prog();
        close_prog();
        return EXIT_FAILURE;
    }

    char **addresses = NULL;
    size_t address_count = read_address_file(address_file_path, &addresses);
    if (address_count == -1) {
        fprintf(stderr, "failed to read addresses from %s\n", address_file_path);
        return EXIT_FAILURE;
    }

    if (populate_targets(targets_map_fd, (const char ***)&addresses, address_count) != 0) {
        fprintf(stderr, "failed to populate the address target map in BPF program\n");
        detach_prog();
        close_prog();
        return EXIT_FAILURE;
    }

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    poll_stats(dropped_map_fd, 2 /* interval seconds */);

    /* never returns */
    return EXIT_SUCCESS;
}

