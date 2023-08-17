struct target_key {
    int addr_family;
    __be32 srcip[4]; /* idx 0 contains the IP for an IP4 address */
};

