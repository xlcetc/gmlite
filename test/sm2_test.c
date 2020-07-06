#include "test.h"

typedef struct
{
    /* private key */
    char *privkey_hex;
    /* public key */
    char *pubkey_x_hex;
    char *pubkey_y_hex;
    /* message */
    char *msg;
    /* hash */
    char *e_hex;
    /* rand */
    char *k_hex;
    /* signature */
    char *r_hex;
    char *s_hex;
}SM2_SIGN_TEST_VECTOR;

static SM2_SIGN_TEST_VECTOR sign_test_vec[] =
{
    /* 1 */
    {
        "837F26CF4A5A9CC5FDE16602CEFF5CFB22B1E3E53D0ADC40FEF1BF6B9EC8371E",
        "E3D37935C0EC25A4552CB76E7CDB92F43D5C80EAD30D7D85D8E87BEA3B6F2746",
        "EA9089635D0705C4BBC19A354A1950A5887D7CBD2DC2F5B266BC0690663B4E5C",
        NULL,
        "B08CDE0B18C8969F9A28787EA5B37023B73B457E26E3B1AFD0E8D93634E110D4",
        "BB9261CC578B75F8BE6F7E9532EC544823F78488BD2E88BA09CB13AC0D4A1080",
        "C17C5787424CA752616D7BBE6259F36821DD404A41C71A049D418CA3AC0295C1",
        "B18EB9348A18B4FB3CDD44D9C9C860AF818E39B6A7D1342C7DA38C44A4483F7A",
    },
    /* 2 */
    {
        "A6EA412B441C5CD6158530FC08B99BA75F27FF6F90B7DE44A8C1F3CC645814A1",
        "5D213DA72310E21D207D7DC7A2DB549CE14647FDCFBEA0DD3A90414E71C5EC7C",
        "80F0ADF6D2158DBDE1715440FE1EE927EB1B4F36E7CC014D47CAF970DF19DD44",
        NULL,
        "C660831C4142E29FD14A0010FF9D37CEE28F1B783BA7F383FF7D77D8321DCC38",
        "577F3845B54A04896D3D0419D08101FCA608E50B00CB869D74BC6B773A44F491",
        "DE953A8842A77A412933CC6D7BF3D86D1350B9F827A7A26158CC5D99990CC149",
        "4D5F7FC64F46524E8E25CEFE41E046FF83922901BD28EF06E837B57AD1F8A74D",
    },
    /* 3 */
    {
        "264CE0AF1DFCB6B1721F598461680D62F7D27A41D859D2DAE70F97D4F014BBF2",
        "2F563ECECFF8DD74FEDC1CCCB69CA8470F0A7E82038BD89655E8320D58B79952",
        "32930F9D9E7D776E920557079CC7FF377A31B983557D779303B66EA62F3C0C3E",
        NULL,
        "73F854AB8669A07EB6366E13F5714FE1DB344CC73E9673349E6BDFFE666666EB",
        "7D9FEE1857C8A54F9DE669DECBE17B4B2F125CB7AF239E7425AA04FEA3347E04",
        "66BF836EA99243F069F06224DF5DF18A0292C6812B40340B1E1A884BD1EFD412",
        "A786A2A2FACABF3910F4D6AA18C4A4D9B1374A8BF00676425D2CF132EDE8B31A",
    },
    /* 4 */
    {
        "6881297C9E9520857BA0B56EB966659AC2D99AD4E8E1152ADCAF8370C3662964",
        "B4A45FC19D9FF1D995C4108E6F9888AB6962FAFF77E3DA2C401F0D28AB131AC7",
        "D46B1F7FCFCC5A29B72170B3D065C1E3CD7ED58EA0EF3856DC6BEBA0F6E2CDE2",
        NULL,
        "7C8E253E7037F5B5948F02BC96FA4F353510A0505E42B0F4916A4C7801DE9D88",
        "4256F178E5824EBEA232F0255EA373CBDACA0E66693AEBB1103A2CAED9FF856E",
        "59C260D3118C4CB1C0B08D9AE6BF48E33E091E9B4197C47BB5D728AD7A04A551",
        "86537C4CD58F415F3254ADEEF842DCB645F07FC30ED4CF98945C2AA40A2DCB3C",
    },
    /* 5 */
    {
        "0000000000000000000000000000000000000000000000000000000000000005",
        "C749061668652E26040E008FDD5EB77A344A417B7FCE19DBA575DA57CC372A9E",
        "F2DF5DB2D144E9454504C622B51CF38F5006206EB579FF7DA6976EFF5FBE6480",
        NULL,
        "7777777777777777777777777777777777777777777777777777777777777777",
        "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
        "B3305AA9C627EA400EC7587DDF359556CA9AC3CABC9285BA55BFFE92A9CF5C73",
        "BD2A31992D5BE49D1B81B369987B2B5ED95609513214BE69C20DC5B85DC926C6",
    },
    /* 6 */
    {
        "6000000000000000000000000000000000000000000000000000000000000006",
        "FACEB1AE43634A9A623425D7C48716B620D89D75A5421F2F12BD976F75348B34",
        "7A7BCEB308E430821CAE634E0AD42173EBFEA0FD5F6CDD9B099F4CD4289C840B",
        NULL,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "344081B80805540A38D71D721BD072D8957EAE15AEB852E72086AB4C5962B89B",
        "B72ED46EF2A74E04C61139B2BF01DEF57E6F17EDA8C1B320CF83BD6EB61BE4DE",
    },
    /* 7 */
    {
        "7777777777777777777777777777777777777777777777777777777777777777",
        "CF8790D90D3961855E8AC41F64FB508718EED1D0EDF73AED6C8B209D7FC78042",
        "C36BBE2775D7920BBAC177A7658E038180407F92D985CAEA7FC287B615C674D6",
        NULL,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
        "2D71E7B03D1CC774BCA9E37F7C835F10E74485A75314001DCEE3BFAF36A65ACA",
    },
    /* 8 */
    {
        "8000000000000000000000000000000000000000000000000000000000000000",
        "DCB53EB5B07C0513881158CFE779F44AA3FA4BFBDAEDA1EB48BB387A1529DB42",
        "571ADB13E629A820F0AB2AD4E5FD9181083D8D22BC54738063D0ACA20746E1AA",
        NULL,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "8888888888888888888888888888888888888888888888888888888888888888",
        "BE06C6806B2AFD7E4AAD7ACCE392394F58F419C71EE67C42E94ED2F8AC2A4A7E",
        "1EFC00D35EF5A18544989591B454C3771CE404191803911526D9E86894AD20F3",
    },
    /* 9 */
    {
        "9000000000000000000000000000000000000000000000000000000000000000",
        "0AEE0A9EACEB15A4F059B3010575474437173334EE97501C4B6723BB9502CF02",
        "4439B6A3F09DCE908584EC5264D193750D242677361D5D4C1857F0588BC36324",
        NULL,
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122",
        "9000000000000000000000000000000000000000000000000000000000000000",
        "0AEE0A9EACEB15A4F059B3010575474437173334EE97501C4B6723BB9502CF01",
        "F66D215DF5E2AF872A5ACDD981DD388356486454FB3965C21EA9DEEDE185B71A",
    },
    /* 10 */
    {
        "1101011110101010010101011001010101010101010101111111110011001101",
        "2E4B459100D45A64C6AF4F23CA255A9822A16EA3919C4221B475F7556DE167D3",
        "11DFA8DE818D60D68DF6E83AE9879FE8B01504AF8D54F37E5D60B65401A905B8",
        NULL,
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122",
        "1101011110101010010101011001010101010101010101111111110011001101",
        "2E4B459100D45A64C6AF4F23CA255A9822A16EA3919C4221B475F7556DE167D2",
        "23E4FD6A0A3FE82F1A6375F1D140ADE05CCCD6293849134D27F1ACD5AA626978",
    },
    /* 11 */
    {
        "91a5b20fcb02a1fc563d7d53b09e060facf70300e20e1a4520a7c1c2b23e9f31",
        "87d847422ba05ac8ccc38ed48a3da3e3e9085c51ef12e4c9fd0eb399be2d29fc",
        "9096a582e77b64b7535322c20e3e92265cd585081526e63f4bafa01cff58b6ce",
        "abcdefg12345678",
        NULL,
        NULL,
        "699213c483b14bcc86c047e43fb9fbcfbe1ba8ffe5796005c6e61445927c0f87",
        "d88ab038b6561c5bbb576cc073284621540bdd70f979e0193122fb02910852d2",
    }
};

static int other_test()
{
    // uint8_t pubkey_x[32], pubkey_y[32], privkey[32], pkx[32], pky[32];
    // uint8_t *priv = "91a5b20fcb02a1fc563d7d53b09e060facf70300e20e1a4520a7c1c2b23e9f31";
    // uint8_t *pkxhex = "87d847422ba05ac8ccc38ed48a3da3e3e9085c51ef12e4c9fd0eb399be2d29fc";
    // uint8_t *pkyhex = "9096a582e77b64b7535322c20e3e92265cd585081526e63f4bafa01cff58b6ce";
    // uint8_t *msg_hex = "308201d0a003020102021015d2aee0f380fa89253033749e0bf23a300a06082a811ccf550183753073310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d53616e204672616e636973636f31193017060355040a13106f7267312e6578616d706c652e636f6d311c301a0603550403131363612e6f7267312e6578616d706c652e636f6d301e170d3230303531383036313331325a170d3330303531363036313331325a306c310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d53616e204672616e636973636f310f300d060355040b1306636c69656e74311f301d06035504030c1641646d696e406f7267312e6578616d706c652e636f6d3059301306072a8648ce3d020106082a811ccf5501822d03420004a20aeefa2234716cf93a2f14d959f3848b9fe4887924cabd318c590174cffd760ed834a6c2731756b702adf8993adb4aed0be347e802d61d5df789dd8ed49cbba34d304b300e0603551d0f0101ff040403020780300c0603551d130101ff04023000302b0603551d23042430228020a75e6ea8625204d798eeca1e3410adbb4cf79615f1c9c64960c0ac5352983edf";
    // int hexlen;
    // uint8_t *msg = "abcdefg12345678";
    // int msglen;
    // unsigned char *id = "1234567812345678";
    // int idlen = 16;
    // uint8_t *sighex = "30450220699213c483b14bcc86c047e43fb9fbcfbe1ba8ffe5796005c6e61445927c0f87022100d88ab038b6561c5bbb576cc073284621540bdd70f979e0193122fb02910852d2";
    // uint8_t sig[128];
    // int siglen;
    // SM2_CTX *sm2_ctx = NULL;
    // sm2_ctx = (SM2_CTX*)CRYPTO_zalloc(sizeof(SM2_CTX));
    // sm2_ctx->pk_precomp = (void*)1;
    // SM2_CTX_init(sm2_ctx, NULL, NULL);
    // SM2_CTX_init(sm2_ctx, NULL, NULL);
    // SM2_CTX_clear(sm2_ctx);
    // SM2_CTX_init(sm2_ctx, NULL, NULL);
    // SM2_CTX_init(sm2_ctx, NULL, NULL);

    // hexlen = strlen(msg_hex);
    // msglen = hexlen / 2;
    // // msg = (uint8_t*)CRYPTO_malloc(msglen);
    // // hex_to_u8(msg_hex, hexlen, msg);
    // hex_to_u8(priv, 64, privkey);
    // hex_to_u8(pkxhex, 64, pubkey_x);
    // hex_to_u8(pkyhex, 64, pubkey_y);
    // // sig = CRYPTO_malloc(strlen(sighex)/2);
    // // hex_to_u8(sighex, strlen(sighex), sig);

    // SM2_compute_pubkey(privkey, pkx, pky);
    // if (CRYPTO_memcmp(pkx, pubkey_x, 32) != 0)
    //     printf("wrong x\n");

    // if (CRYPTO_memcmp(pky, pubkey_y, 32) != 0)
    //     printf("wrong y\n");

    // // if (SM2_sign_ex(sig, &siglen, msg, 15, id, idlen, NULL, pubkey_x, pubkey_y, privkey, 0, sm2_ctx) == NULL)
    // //     printf("sign\n");
    // // print_hex("sig:", sig, siglen);

    // // if (SM2_verify_ex(sig, siglen, msg, 15, id, idlen, pubkey_x, pubkey_y, SM2_SIG_RS_ASN1, sm2_ctx) == GML_ERROR)
    // //     printf("bad\n");

    // // CRYPTO_free(msg);
    // // CRYPTO_free(sig);
    // // SM2_CTX_clear(sm2_ctx);
    // SM2_CTX_clear_free(sm2_ctx);
    return 1;
}

static int sm2_sign_cases()
{
    int ret = GML_ERROR;

    /* signature asn1 */
    uint8_t sig[128];
    uint8_t tsig[128]; int tsiglen;
    uint8_t ttsig[128]; int ttsiglen;
    /* message */
    uint8_t *msg;
    int msglen;
    /* id */
    unsigned char *id = (uint8_t*)"1234567812345678";
    int idlen = 16;
    /* k(rand) */
    uint8_t k[32];
    /* e = SM3(ZA || m) */
    uint8_t e[32];
    /* private key */
    uint8_t privkey[32];
    /* public key */
    uint8_t pubkey_x[32], pubkey_y[32];
    uint8_t tpubkey_x[32], tpubkey_y[32];
    SM2_CTX *sm2_ctx = NULL;
    sm2_ctx = (SM2_CTX*)CRYPTO_zalloc(sizeof(SM2_CTX));

    for (int i = 0; i < sizeof(sign_test_vec) / sizeof(SM2_SIGN_TEST_VECTOR); i++) {
        hex_to_u8((uint8_t*)sign_test_vec[i].r_hex, 64, sig);
        hex_to_u8((uint8_t*)sign_test_vec[i].s_hex, 64, sig + 32);
        if (sign_test_vec[i].e_hex != NULL)
            hex_to_u8((uint8_t*)sign_test_vec[i].e_hex, 64, e);
        if (sign_test_vec[i].k_hex != NULL)
            hex_to_u8((uint8_t*)sign_test_vec[i].k_hex, 64, k);
        hex_to_u8((uint8_t*)sign_test_vec[i].privkey_hex, 64, privkey);
        hex_to_u8((uint8_t*)sign_test_vec[i].pubkey_x_hex, 64, pubkey_x);
        hex_to_u8((uint8_t*)sign_test_vec[i].pubkey_y_hex, 64, pubkey_y);

        SM2_CTX_init(sm2_ctx, pubkey_x, pubkey_y);

        if (SM2_compute_pubkey(privkey, tpubkey_x, tpubkey_y) != GML_OK) {
            printf("sm2_sign_cases %d SM2_compute_pubkey FAIL\n", i+1);
            goto end;
        }

        if (memcmp(pubkey_x, tpubkey_x, 32) != 0) {
            printf("sm2_sign_cases %d wrong keypair\n", i+1);
            goto end;
        }

        if (sign_test_vec[i].e_hex != NULL) {
            if (SM2_sign(tsig, &tsiglen, e, k, privkey, SM2_SIG_RS_ORIG, sm2_ctx) != GML_OK) {
                printf("sm2_sign_cases %d SM2_sign FAIL\n", i+1);
                goto end;
            }

            if (sign_test_vec[i].k_hex != NULL) {
                if (memcmp(sig, tsig, tsiglen) != 0) {
                    printf("sm2_sign_cases %d wrong signature\n", i+1);
                    goto end;
                }
            }

            if (SM2_verify(tsig, tsiglen, e, pubkey_x, pubkey_y, SM2_SIG_RS_ORIG, sm2_ctx) != GML_OK) {
                printf("sm2_sign_cases %d SM2_verify FAIL\n", i+1);
                goto end;
            }
        }

        if (sign_test_vec[i].msg != NULL) {
            // msglen = strlen(sign_test_vec[i].msg) / 2;
            // msg = CRYPTO_malloc(msglen);
            // hex_to_u8((uint8_t*)sign_test_vec[i].msg, msglen*2, msg);
            msg = (uint8_t*)sign_test_vec[i].msg;
            msglen = strlen((const char*)msg);

            if (SM2_sign_ex(ttsig, &ttsiglen, msg, msglen, id, idlen, k, pubkey_x, pubkey_y, privkey, SM2_SIG_RS_ORIG, sm2_ctx) != GML_OK) {
                printf("sm2_sign_cases %d SM2_sign_ex FAIL\n", i+1);
                goto end;
            }

            if (sign_test_vec[i].k_hex != NULL) {
                if (memcmp(sig, ttsig, ttsiglen) != 0) {
                    printf("sm2_sign_cases %d ex wrong signature\n", i+1);
                    goto end;
                }
            }

            if (SM2_verify_ex(ttsig, ttsiglen, msg, msglen, id, idlen, pubkey_x, pubkey_y, SM2_SIG_RS_ORIG, sm2_ctx) != GML_OK) {
                printf("sm2_sign_cases %d SM2_verify_ex FAIL\n", i+1);
                goto end;
            }

            // CRYPTO_free(msg);
            // msglen = 0;
        }
        SM2_CTX_clear(sm2_ctx);
    }

    other_test();

    SM2_CTX_clear_free(sm2_ctx);
    printf("sm2_sign_cases PASS\n");
    ret = GML_OK;
end:
    return ret;
}

/* hash test */
static void sm2_sign_hash_test(void *p)
{
    int N;

    /* 签名 */
    uint8_t sig[128];
    int siglen;
    /* e = SM3(ZA || m) */
    uint8_t e[32];
    /* 私钥 r */
    uint8_t privkey[32];
    /* 公钥 (x, y) */
    uint8_t pubkey_x[32];
    uint8_t pubkey_y[32];
    /* mode */
    int mode;
    SM2_CTX *sm2_ctx = NULL;
    sm2_ctx = (SM2_CTX*)CRYPTO_zalloc(sizeof(SM2_CTX));

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N;

    for (int i = 0; i < N; i++) {
        /* random hash */
        random_string(e, 32);

        /* random mode */
        mode = random_number() % 2;

        /* random key */
        if (SM2_keygen(privkey, pubkey_x, pubkey_y) == GML_ERROR) {
            printf("第 %d 次sm2 keygen failed \n", i+1);
            args->ok = GML_ERROR;
            return;
        }
        
        if (SM2_CTX_init(sm2_ctx, NULL, NULL) == GML_ERROR) {
            printf("第 %d 次sm2 ctx init failed \n", i+1);
            args->ok = GML_ERROR;
            return;
        }

        /* signature */
        if (SM2_sign(sig, &siglen, e, NULL, privkey, mode, sm2_ctx) == GML_ERROR) {
            printf("第 %d 次sm2 hash sign failed \n", i+1);
            args->ok = GML_ERROR;
            return;
        }

        /* verify signature */
        if (SM2_verify(sig, siglen, e, pubkey_x, pubkey_y, mode, sm2_ctx) == GML_ERROR) {
            printf("第 %d 次sm2 hash verify failed \n", i+1);
            // /* */
            // print_hex("e:        ", e, 32);
            // print_hex("r:        ", r, 32);
            // print_hex("s:        ", s, 32);
            // print_hex("privkey :", privkey, 32);
            // print_hex("pubkey_x:", pubkey_x, 32);
            // print_hex("pubkey_y:", pubkey_y, 32);
            // printf("==================================\n");
            // /* */
            args->ok = GML_ERROR;
            return;
        }

        SM2_CTX_clear(sm2_ctx);
    }

    SM2_CTX_clear_free(sm2_ctx);
    printf("%d 次 sm2 hash sign and verify PASS \n", N);
    args->ok = GML_OK;
    return;
}

/* message test */
static void sm2_sign_msg_test(void *p)
{
    int N;

    /* 签名 */
    uint8_t sig[128];
    int siglen;
    /* message */
    uint8_t msg[256];
    int msglen;
    /* id */
    unsigned char id[32];
    int idlen = 18;
    /* 私钥 r */
    uint8_t privkey[32];
    /* 公钥 (x, y) */
    uint8_t pubkey_x[32];
    uint8_t pubkey_y[32];
    /* mode */
    int mode;
    SM2_CTX *sm2_ctx = NULL;
    sm2_ctx = (SM2_CTX*)CRYPTO_zalloc(sizeof(SM2_CTX));

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N;

    for (int i = 0; i < N; i++) {
        /* random message */
        msglen = random_number() % 256;
        random_string(msg, msglen);

        /* random key */
        SM2_keygen(privkey, pubkey_x, pubkey_y);
        // memset(sm2_ctx, 0, sizeof(SM2_CTX));
        if (SM2_CTX_init(sm2_ctx, NULL, NULL) == GML_ERROR) {
            printf("第 %d 次SM2_CTX_init failed \n", i+1);
            args->ok = GML_ERROR;
            return;
        }

        /* random mode */
        mode = random_number() % 2;

        /* signature */
        if (SM2_sign_ex(sig, &siglen, msg, msglen, id, idlen, NULL, pubkey_x, pubkey_y, privkey, mode, sm2_ctx) == GML_ERROR) {
            printf("第 %d 次sm2 message sign failed \n", i+1);
            args->ok = GML_ERROR;
            return;
        }

        /* */
        if (SM2_verify_ex(sig, siglen, msg, msglen, id, idlen, pubkey_x, pubkey_y, mode, sm2_ctx) == GML_ERROR) {
            printf("第 %d 次sm2 message verify failed \n", i+1);
            // /* */
            // print_hex("e:        ", e, 32);
            // print_hex("r:        ", r, 32);
            // print_hex("s:        ", s, 32);
            // print_hex("privkey :", privkey, 32);
            // print_hex("pubkey_x:", pubkey_x, 32);
            // print_hex("pubkey_y:", pubkey_y, 32);
            // printf("==================================\n");
            // /* */
            args->ok = GML_ERROR;
            return;
        }

        SM2_CTX_clear(sm2_ctx);
    }

    SM2_CTX_clear_free(sm2_ctx);
    printf("%d 次 sm2 message sign and verify PASS \n", N);
    args->ok = GML_OK;
    return;
}

/* sm2 enc, dec test */
static void sm2_enc_test(void *p)
{
    int N;

    /* plaintext p */
    uint8_t pt[128];
    int plen;

    /* ciphertext c */
    uint8_t *c = NULL;
    int clen;

    /*  */
    uint8_t *z = NULL;
    int zlen;

    /* private key */
    uint8_t privkey[32];

    /* public key (x, y) */
    uint8_t pubkey_x[32];
    uint8_t pubkey_y[32];

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N;

    for (int i = 0; i < N; i++) {
        plen = random_number() % 128 + 1;

        /* random plaintext */
        random_string(pt, plen);

        /* random key */
        SM2_keygen(privkey, pubkey_x, pubkey_y);

        /* signature */
        if (SM2_encrypt(&c, &clen, pt, plen, pubkey_x, pubkey_y) == GML_ERROR) {
            printf("第 %d 次sm2 enc failed \n", i+1);
            args->ok = GML_ERROR;
            return;
        }

        /* */
        if (SM2_decrypt(&z, &zlen, c, clen, privkey) == GML_ERROR) {
            printf("第 %d 次sm2 dec failed \n", i+1);
            // print_hex("msg:      ", pt, 67);
            // print_hex("cipher:   ", c, 67+97);
            // print_hex("privkey :", privkey, 32);
            // print_hex("pubkey_x:", pubkey_x, 32);
            // print_hex("pubkey_y:", pubkey_y, 32);
            // printf("==================================\n");
            args->ok = GML_ERROR;
            return;
        }

        if (zlen != plen || CRYPTO_memcmp(z, pt, plen != 0)) {
            printf("第 %d 次 sm2 wrong decryption\n", i+1);
            args->ok = GML_ERROR;
            return;
        }

        CRYPTO_free(c);
        CRYPTO_free(z);
        c = NULL;
        z = NULL;
    }

    printf("%d 次 sm2 enc and dec PASS \n", N);
    args->ok = GML_OK;
    return;
}

int main(int argc, char **argv)
{
    int ret;
    if (CRYPTO_init() == GML_ERROR)
        return -1;

    TEST_ARGS args;
    args.ok = 0;
    args.N = 12345;
    args.num_threads = 4;
    get_test_arg(argc, argv, &args);

    if(sm2_sign_cases() != GML_OK) return -1;

    /* single thread test */
    printf("-----------SM2 HASH SIGN VERIFY SINGLE THREAD TEST------------ \n");
    sm2_sign_hash_test((void*)&args); if(args.ok == GML_ERROR) return -1;

    /* multi thread test */
    printf("\n-----------SM2 HASH SIGN VERIFY MULTI THREAD TEST------------- \n");
    printf("number of threads : %ld \n\n", args.num_threads);
    ret = test_start_n_thread(sm2_sign_hash_test, &args); if(ret == GML_ERROR) return -1;

    /* single thread test */
    printf("-----------SM2 MESSAGE SIGN VERIFY SINGLE THREAD TEST------------ \n");
    sm2_sign_msg_test((void*)&args); if(args.ok == GML_ERROR) return -1;

    /* multi thread test */
    printf("\n-----------SM2 MESSAGE SIGN VERIFY MULTI THREAD TEST------------- \n");
    printf("number of threads : %ld \n\n", args.num_threads);
    ret = test_start_n_thread(sm2_sign_msg_test, &args); if(ret == GML_ERROR) return -1;

    /* single thread test */
    printf("-----------SM2 ENC DEC SINGLE THREAD TEST------------ \n");
    sm2_enc_test((void*)&args); if(args.ok == GML_ERROR) return -1;

    /* multi thread test */
    printf("\n-----------SM2 MESSAGE ENC DEC MULTI THREAD TEST------------- \n");
    printf("number of threads : %ld \n\n", args.num_threads);
    ret = test_start_n_thread(sm2_enc_test, &args); if(ret == GML_ERROR) return -1;

    CRYPTO_deinit();
    return 0;
}

