#ifndef BITCOIN_CHAINPARAMSSEEDS_H
#define BITCOIN_CHAINPARAMSSEEDS_H
/**
 * List of fixed seed nodes for the bitcoin network
 * AUTOGENERATED by contrib/seeds/generate-seeds.py
 *
 * Each line contains a 16-byte IPv6 address and a port.
 * IPv4 as well as onion addresses are wrapped inside an IPv6 address accordingly.
 */
static SeedSpec6 pnSeed6_main[] = {
    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff, 185, 231,  70,  34},  9987},
    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff, 193, 124,  64, 184},  9987},
//    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x68,0x1C,0x07,0x84}, 23153}, 
//    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x05,0x2d,0x4f,0x0e}, 8333}
};

static SeedSpec6 pnSeed6_test[] = {
    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff, 185, 231,  70,  34},  9987},
    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff, 193, 124,  64, 184},  9987},
//    {{0xfd,0x87,0xd8,0x7e,0xeb,0x43,0x6a,0x8b,0xd2,0x78,0x3f,0x7a,0xf8,0x92,0x8f,0x80}, 18333},
//    {{0xfd,0x87,0xd8,0x7e,0xeb,0x43,0xe6,0x4e,0xa4,0x47,0x4e,0x2a,0xfe,0xe8,0x95,0xcc}, 18333}
};
#endif // BITCOIN_CHAINPARAMSSEEDS_H