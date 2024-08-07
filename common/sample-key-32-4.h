uint8_t	_key_beta[NUM_BETA_KEYS][SIMD_ENCRYPT_SIZE] = {{0x27, 0x8b, 0xcf, 0x61, 0xcc, 0x1d, 0xca, 0xa6, 0x97, 0x7a, 0x0a, 0x70, 0x08, 0x65, 0xaf, 0x79, 0x91, 0x95, 0x75, 0x52, 0xbd, 0x56, 0xa9, 0x8d, 0x68, 0x99, 0x4f, 0xd1, 0x79, 0x11, 0xec, 0x49, 0x46, 0x82, 0xfa, 0x97, 0xf2, 0xb3, 0xf1, 0xd6, 0x90, 0x2a, 0xc9, 0x62, 0xad, 0xe2, 0x98, 0xa6, 0x72, 0x0a, 0x61, 0xc9, 0x5d, 0x16, 0xbd, 0xa2, 0xa2, 0x32, 0x0d, 0x25, 0x22, 0xf0, 0xd0, 0x49, 0x5d, 0xfd, 0x94, 0xdb, 0x0b, 0x3c, 0x9d, 0x38, 0xc9, 0x99, 0x6a, 0xac, 0x02, 0x28, 0xd6, 0x0c, 0xaa, 0x4f, 0xe1, 0x83, 0x3a, 0xa4, 0x7b, 0x1a, 0xd7, 0x6b, 0x5d, 0x48, 0x4c, 0xf0, 0xcd, 0x79, 0x27, 0x7b, 0x53, 0xe5, 0x5f, 0x13, 0x9c, 0x00, 0xfc, 0x6a, 0xff, 0x36, 0x30, 0x38, 0xa0, 0xa8, 0x17, 0x00, 0xc1, 0x07, 0x4e, 0x92, 0x4d, 0x25, 0x48, 0xeb, 0xf6, 0x19, 0x98, 0x93, 0xe8, 0x14}, {0xac, 0x1e, 0x3a, 0x6c, 0x3a, 0x32, 0xc5, 0xe0, 0x57, 0x83, 0x4f, 0xad, 0x20, 0x3c, 0x87, 0xe7, 0x93, 0x32, 0xfa, 0x78, 0x81, 0xef, 0xee, 0xf1, 0x49, 0x35, 0xa9, 0xe1, 0x41, 0x98, 0x6a, 0x27, 0xa3, 0x2d, 0x41, 0xc5, 0xe0, 0x7f, 0x7f, 0xf2, 0xfc, 0x68, 0x09, 0x16, 0x9d, 0x5a, 0xb7, 0x22, 0x51, 0xc8, 0x8b, 0x59, 0xc3, 0x18, 0x30, 0xf4, 0x4f, 0x14, 0x0a, 0x02, 0x01, 0x7d, 0xe0, 0xaf, 0xfc, 0x95, 0x27, 0x0e, 0xe1, 0xb0, 0xaf, 0xae, 0x40, 0x19, 0x4e, 0x24, 0xd5, 0x8f, 0xf0, 0x74, 0xe7, 0x47, 0xc8, 0x57, 0x67, 0x4f, 0xae, 0x1c, 0xb6, 0x25, 0x37, 0x25, 0x81, 0x5c, 0xcf, 0xa0, 0xab, 0x68, 0xf1, 0x3b, 0xd0, 0x2d, 0xe0, 0x04, 0x33, 0x29, 0x34, 0xfd, 0x69, 0x04, 0x14, 0x13, 0x34, 0x60, 0x7c, 0x97, 0x21, 0xdf, 0xcd, 0xb8, 0xf5, 0x39, 0x82, 0xd8, 0x01, 0xbb, 0xea, 0xb4}, {0x99, 0x6a, 0x32, 0x74, 0xa5, 0x82, 0xef, 0xe9, 0x1e, 0x98, 0x53, 0x3d, 0xec, 0xf3, 0x75, 0x9a, 0xeb, 0x94, 0xe8, 0x47, 0x4d, 0xc6, 0x2e, 0x1b, 0x07, 0xab, 0x48, 0x19, 0x4b, 0x52, 0x93, 0xe0, 0x2b, 0x25, 0x91, 0xfd, 0xec, 0xe4, 0xda, 0x78, 0xd5, 0x68, 0x05, 0x9e, 0xd9, 0xb1, 0xb3, 0x2b, 0xc7, 0x62, 0xce, 0x22, 0x60, 0xde, 0x07, 0xce, 0x6a, 0xa8, 0x88, 0x0f, 0x0b, 0x3a, 0xd7, 0xc8, 0x2e, 0x35, 0x75, 0xb2, 0xe2, 0x38, 0x1d, 0x15, 0x17, 0x65, 0x9a, 0xe0, 0xb0, 0x3f, 0x02, 0x6d, 0xa1, 0x82, 0x93, 0x8f, 0xcf, 0x2e, 0x91, 0xcb, 0xb3, 0x63, 0x7c, 0x98, 0x03, 0x41, 0x63, 0x95, 0x6a, 0x37, 0xd9, 0x91, 0x58, 0x25, 0xbb, 0xd6, 0xfe, 0x0e, 0x52, 0xde, 0x17, 0xf4, 0xf7, 0xa5, 0xa6, 0xf6, 0x8e, 0xb3, 0x1b, 0x9a, 0x5e, 0x56, 0x55, 0xbb, 0x79, 0x8f, 0xca, 0x75, 0x3b, 0x2b}};
uint8_t	_init_prev_c_prime[HNC_RANK * 32] = {0xe5, 0xc4, 0xd6, 0x62, 0xb9, 0x77, 0xde, 0x24, 0xe3, 0x7f, 0xa0, 0x3a, 0xae, 0xd2, 0x17, 0xca, 0x94, 0x15, 0xa6, 0x76, 0x57, 0xbf, 0x9c, 0xab, 0x99, 0xd6, 0x25, 0x7b, 0xd1, 0x93, 0xd5, 0xdb, 0xac, 0xae, 0x02, 0x30, 0x22, 0xda, 0xae, 0xf4, 0xb2, 0x9c, 0x6c, 0xa6, 0x6f, 0x87, 0x72, 0x99, 0x66, 0x68, 0x1e, 0xa8, 0x56, 0x11, 0x91, 0xaf, 0xf7, 0x34, 0x48, 0x58, 0x63, 0xf6, 0x41, 0x6f, 0x70, 0xa6, 0xd7, 0x44, 0x4e, 0xa6, 0x4d, 0x73, 0x7e, 0xa2, 0x03, 0x72, 0x3e, 0x7c, 0xa4, 0x80, 0x00, 0x2f, 0x44, 0x76, 0x5b, 0x02, 0x2a, 0x73, 0xb5, 0x68, 0x1a, 0x7b, 0xc1, 0x1a, 0x1c, 0x8b, 0xaf, 0xfb, 0xfa, 0xf8, 0x92, 0xd3, 0x24, 0x4a, 0x20, 0xee, 0xfc, 0xa2, 0xef, 0xc2, 0x18, 0x61, 0xfb, 0x5c, 0x80, 0xcb, 0x6b, 0xa2, 0x88, 0xbc, 0x58, 0x16, 0xc2, 0x49, 0x84, 0xc6, 0xdf, 0xed};
static uint32_t	_key_mtrx_enc[NUM_MTRX_KEYS][HNC_RANK][HNC_RANK] = {{{0xbb38c6b4, 0xdd3353c4, 0x42796f96, 0x5e2a2935}, {0x565286fc, 0xc1a8fe2f, 0xea926712, 0x692b2197}, {0xf24a3e1c, 0xda56880b, 0xf7395a8d, 0x9669583f}, {0x13eb5a23, 0x006aca19, 0x9e3db32b, 0x6d606aec}}, {{0x12806e3d, 0x42fa7905, 0xabb6f474, 0xc2eb163d}, {0x4a6bdc70, 0x0749f519, 0x152692fc, 0xc72bec13}, {0x3d7ebac8, 0xf6fc2e3e, 0xf20c4091, 0xd3e3dc49}, {0x402bcfc5, 0xc7987932, 0x9c62034a, 0x6731a371}}, {{0xfd690b8a, 0x5afe5a63, 0x5fc2ebf9, 0x35010eba}, {0x82ad6bc5, 0xbd6de80e, 0xcb3a7b4a, 0x70bc8fd2}, {0x22637238, 0xd619f653, 0xea1e20a0, 0x8757e97f}, {0xe8fcda58, 0x17468dcb, 0xe951038a, 0x1ed19784}}, {{0x49a04f76, 0xe5322df4, 0xbe2e4712, 0xae0e954b}, {0xf977bf44, 0x7ed5b699, 0x80ac7c1b, 0x9745720b}, {0x4fe7d262, 0x9ba9c9a3, 0x0dd04ae8, 0xa99aec60}, {0x0b366897, 0xd9cde088, 0xff273944, 0x9c59fe58}}, {{0xe520674d, 0xb7fb0c6f, 0x55e7aaa3, 0x31bdaaac}, {0x29d5f28f, 0x43bfb27b, 0xfceabb49, 0x68d7852f}, {0x9cf50b21, 0x147e9c9b, 0x9a229c8a, 0x4bf9bdc9}, {0xbb1f5d55, 0x059e1d7e, 0x8864496e, 0xb66ebc33}}, {{0x5f750874, 0x8ff93c39, 0xc7f928a2, 0x9d1d05bc}, {0x4be48f3d, 0xdcac93e6, 0x1d644268, 0x08531e6b}, {0x5f3ea2f9, 0x30ecc7a8, 0x56ba98b4, 0x42a3bc84}, {0x75cbb667, 0x417dbade, 0xc78e7aa7, 0x45f06510}}, {{0xc362bd86, 0xc837f2a9, 0x6133b03b, 0x928bf99e}, {0xe7e84b07, 0xae51aff1, 0xcbbdb715, 0xe6518359}, {0xd1088efe, 0x13c56ebc, 0x305e6c1c, 0xa0ca6aa3}, {0x20d10806, 0x91d4040b, 0xe0d8a226, 0x5bed4e3c}}, {{0xe9e98be8, 0xf7db5df4, 0xedb358d0, 0x053f1b29}, {0x64ac772d, 0x9233c77f, 0x4785a2c9, 0xd67ff7e6}, {0x98c66e25, 0x24fb6adc, 0x7f060ede, 0xd443aa2c}, {0xc956c2f5, 0x0602e423, 0xad7d29ca, 0x2562e060}}};
static uint32_t	_key_mtrx_dec[NUM_MTRX_KEYS][HNC_RANK][HNC_RANK] = {{{0x9f0db33b, 0x114c265e, 0x2f1b0b4d, 0x884822bb}, {0x6d5bb377, 0x53ad1f6b, 0xc35851c0, 0xf0f26200}, {0x7a39bbbc, 0xdff67be1, 0x923c7b63, 0x0fc6b280}, {0xa17d605d, 0x3f37604e, 0x47d1c5b2, 0x68c4f9f4}}, {{0x601a5fcf, 0xb1118229, 0xbc28f5dc, 0xb2b41046}, {0x961e8d61, 0xbe95674a, 0x98d08fee, 0xbf20bb77}, {0xc71c0719, 0x3f81eb23, 0x13e87183, 0xce4ef707}, {0xd62ae899, 0x326eb371, 0x94b5fafa, 0x1bfd074f}}, {{0x13e2352a, 0xe8aa4259, 0xbb125ffe, 0x9c7a605e}, {0xc866ba76, 0xe3ad00bc, 0x15cd2e68, 0x1e8f8b3d}, {0x0c776c1f, 0x2fe014aa, 0x840c8e76, 0xbdd1eebf}, {0x3dc7abd2, 0x528d16ac, 0xd1988387, 0xd95e7537}}, {{0x765b1cb4, 0x1ff5e294, 0x95fa16ec, 0xd200dec7}, {0x213d7060, 0x64007110, 0x9581324b, 0x50c690c6}, {0x8398c10f, 0x13e9be91, 0x04bdec79, 0xc000ddc0}, {0x07da9691, 0x6444e242, 0x6b7c156e, 0xb439dc6a}}, {{0x7a0a409f, 0x0fdde819, 0xdc222a3a, 0xcdaab8c9}, {0x6874b092, 0x7e78bd5e, 0xabd519cd, 0x2139e78b}, {0x1cd2d894, 0x0f058657, 0x604b7c61, 0x8a62f5da}, {0xfa04813b, 0x36b5babf, 0xc735ab2e, 0xb484001a}}, {{0x6406e7e8, 0xd2d91334, 0xdb5f1609, 0xf0ca71e4}, {0x6fe62085, 0x57c24e24, 0xc5ac32ca, 0xa81c8b22}, {0xc18c283e, 0x822ae534, 0xba0f9d93, 0x28fefb8f}, {0x63a95c9e, 0x63cb90af, 0x0b5d8ab5, 0xed753018}}, {{0xb525539b, 0xeb101433, 0xecafbfe1, 0x8a02f80a}, {0x2224ef70, 0x2ba015c2, 0x0e127e16, 0x05921935}, {0x6e4f4b91, 0xa2ed61d0, 0x83957662, 0xb239d7dd}, {0x6849ef1e, 0x4ea635fa, 0x8c15e7c1, 0x96c00ed4}}, {{0x9622ab70, 0x74ab7b96, 0x61523529, 0x6233639e}, {0x9deec63c, 0xd2e8bd54, 0x05fe2fb9, 0xee3fe843}, {0x55961bc6, 0x8937cfdf, 0x1a0a4b4c, 0x56b0fd3d}, {0x79f98009, 0x2f05ac50, 0x06b8a724, 0x5f777bc4}}};
