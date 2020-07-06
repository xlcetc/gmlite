#include "test.h"
#include "../gmlite/sm9/sm9_lcl.h"

#define TEST_SM9_MSG_MAX_LENGTH 250
#define TEST_SM9_ID_MAX_LENGTH  250

struct SM9_H_CASE
{
    char *a;
    char *b;
    char *h;
    int z; // z=1 : sm9_H1; z=2 : sm9_H2
};

struct SM9_H_CASE sm9_h_case[] = 
{
    {
        "416C696365",
        "01",
        "2ACC468C3926B0BDB2767E99FF26E084DE9CED8DBC7D5FBF418027B667862FAB",
        1,
    },
    {
        "416C696365",
        "02",
        "A9AC0FDA7380ED8E3325FDDCD40A7221E3CD72F6FFA7F27D54AD494CEDB4E212",
        1,
    },
    {
        "426F62",
        "03",
        "9CB1F6288CE0E51043CE72344582FFC301E0A812A7F5F2004B85547A24B82716",
        1,
    },
    {
        "4368696E65736520494253207374616E64617264",
        "81377B8FDBC2839B4FA2D0E0F8AA6853BBBE9E9C4099608F8612C6078ACD7563815AEBA217AD502DA0F48704CC73CABB3C06209BD87142E14CBD99E8BCA1680F30DADC5CD9E207AEE32209F6C3CA3EC0D800A1A42D33C73153DED47C70A39D2E8EAF5D179A1836B359A9D1D9BFC19F2EFCDB829328620962BD3FDF15F2567F58A543D25609AE943920679194ED30328BB33FD15660BDE485C6B79A7B32B013983F012DB04BA59FE88DB889321CC2373D4C0C35E84F7AB1FF33679BCA575D67654F8624EB435B838CCA77B2D0347E65D5E46964412A096F4150D8C5EDE5440DDF0656FCB663D24731E80292188A2471B8B68AA993899268499D23C89755A1A89744643CEAD40F0965F28E1CD2895C3D118E4F65C9A0E3E741B6DD52C0EE2D25F5898D60848026B7EFB8FCC1B2442ECF0795F8A81CEE99A6248F294C82C90D26BD6A814AAF475F128AEF43A128E37F80154AE6CB92CAD7D1501BAE30F750B3A9BD1F96B08E97997363911314705BFB9A9DBB97F75553EC90FBB2DDAE53C8F68E42",
        "823C4B21E4BD2DFE1ED92C606653E996668563152FC33F55D7BFBB9BD9705ADB",
        2,
    },
};

static void sm9_H1_H2_test_case(void *p)
{
    uint8_t *a, *b, *hh;
    int ahexlen, alen, bhexlen, blen;
    BIGNUM *h = NULL;
    const BIGNUM *order = NULL;
    const EC_GROUP *group = NULL;

    TEST_ARGS *args = (TEST_ARGS*)p;
    h = BN_new();
    group = SM9_get_group();
    order = EC_GROUP_get0_order(group);

    for (int i = 0; i < sizeof(sm9_h_case)/sizeof(struct SM9_H_CASE); i++) {
        ahexlen = strlen(sm9_h_case[i].a);
        bhexlen = strlen(sm9_h_case[i].b);
        alen = ahexlen / 2;
        blen = bhexlen / 2;
        a = (uint8_t*)CRYPTO_malloc(alen);
        b = (uint8_t*)CRYPTO_malloc(blen);
        hex_to_u8((const uint8_t*)sm9_h_case[i].a, ahexlen, a);
        hex_to_u8((const uint8_t*)sm9_h_case[i].b, bhexlen, b);
        if (sm9_h_case[i].z == 1)
            sm9_H1(h, a, alen, b, blen, order);
        else
            sm9_H2(h, a, alen, b, blen, order);

        hh = (uint8_t*)BN_bn2hex(h);
        if (CRYPTO_memcmp(hh, (uint8_t*)sm9_h_case[i].h, 64) != 0) {
            print_hex("a:", a, alen);
            print_hex("b:", b, blen);
            printf("%s\n", sm9_h_case[i].h);
            printf("%s\n", hh);
            printf("sm9_H test FAIL\n");
            args->ok = 0;
            BN_free(h);
            CRYPTO_free(a);
            CRYPTO_free(b);
            return;
        }
        CRYPTO_free(hh);
        CRYPTO_free(a);
        CRYPTO_free(b);
    }

    args->ok = GML_OK;
    printf("sm9_H test PASS\n");
    BN_free(h);
}

typedef struct
{
    /* master key */
    char *master_privkey_hex;
    char *master_pubkey_xa_hex;
    char *master_pubkey_xb_hex;
    char *master_pubkey_ya_hex;
    char *master_pubkey_yb_hex;
    /* id */
    char *id;
    /* hid */
    char hid;
    /* user key */
    char *user_privkey_x_hex;
    char *user_privkey_y_hex;
    /* message */
    char *msg;
    /* rand */
    char *r_hex;
    /* signature */
    char *h_hex;
    char *S_hex;
}SM9_SIGN_TEST_VECTOR;

static SM9_SIGN_TEST_VECTOR sign_test_vec[] =
{
    /* 1 (from sm9 standard : www.oscca.gov.cn/sca/xxgk/2016-03/28/content_1002407.shtml) */
    {
        "000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4",
        "9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408",
        "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32",
        "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25",
        "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D",
        "Alice",
        0x01,
        "A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820",
        "78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3",
        "Chinese IBS standard",
        "00033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE",
        "823C4B21E4BD2DFE1ED92C606653E996668563152FC33F55D7BFBB9BD9705ADB",
        "0473BF96923CE58B6AD0E13E9643A406D8EB98417C50EF1B29CEF9ADB48B6D598C856712F1C2E0968AB7769F42A99586AED139D5B8B3E15891827CC2ACED9BAA05",
    },
};

static int sm9_sign_cases()
{
    int ret = GML_ERROR;

    uint8_t *id;
    uint8_t hid;
    uint8_t *msg;

    /* signature h, S */
    uint8_t h[32], S[65];
    uint8_t th[32], tS[65];

    /* r(rand) */
    uint8_t r[32];

    /* master key */
    uint8_t master_privkey[32];
    uint8_t master_pubkey[129], tmaster_pubkey[129];

    /* user key */
    uint8_t user_privkey[65], tuser_privkey[65];

    for (int i = 0; i < sizeof(sign_test_vec) / sizeof(SM9_SIGN_TEST_VECTOR); i++) {
        id = (uint8_t*)sign_test_vec[i].id;
        hid = (uint8_t)sign_test_vec[i].hid;
        msg = (uint8_t*)sign_test_vec[i].msg;
        hex_to_u8((uint8_t*)sign_test_vec[i].h_hex, 64, h);
        hex_to_u8((uint8_t*)sign_test_vec[i].S_hex, 130, S);
        hex_to_u8((uint8_t*)sign_test_vec[i].r_hex, 64, r);
        hex_to_u8((uint8_t*)sign_test_vec[i].master_privkey_hex, 64, master_privkey);
        master_pubkey[0] = 0x04U;
        hex_to_u8((uint8_t*)sign_test_vec[i].master_pubkey_xa_hex, 64, master_pubkey + 1);
        hex_to_u8((uint8_t*)sign_test_vec[i].master_pubkey_xb_hex, 64, master_pubkey + 1 + 32);
        hex_to_u8((uint8_t*)sign_test_vec[i].master_pubkey_ya_hex, 64, master_pubkey + 1 + 64);
        hex_to_u8((uint8_t*)sign_test_vec[i].master_pubkey_yb_hex, 64, master_pubkey + 1 + 96);
        user_privkey[0] = 0x04U;
        hex_to_u8((uint8_t*)sign_test_vec[i].user_privkey_x_hex, 64, user_privkey + 1);
        hex_to_u8((uint8_t*)sign_test_vec[i].user_privkey_y_hex, 64, user_privkey + 1 + 32);

        if (SM9_compute_master_pubkey(master_privkey, tmaster_pubkey) != GML_OK) {
            printf("sm9_sign_cases SM9_compute_master_pubkey %d FAIL\n", i+1);
            goto end;
        }

        if (memcmp(master_pubkey, tmaster_pubkey, 129) != 0) {
            printf("sm9_sign_cases %d wrong master key pair\n", i+1);
            goto end;
        }

        if (SM9_usr_keygen(tuser_privkey, id, strlen((char*)id), hid, master_privkey) != GML_OK) {
            printf("sm9_sign_cases SM9_usr_keygen %d FAIL\n", i+1);
            goto end;
        }

        if (memcmp(user_privkey, tuser_privkey, 65) != 0) {
            printf("sm9_sign_cases %d wrong user private key\n", i+1);
            goto end;
        }

        if (SM9_sign(th, tS, msg, strlen((char*)msg), r, user_privkey, master_pubkey) != GML_OK) {
            printf("sm9_sign_cases SM9_sign %d FAIL\n", i+1);
            goto end;
        }

        if (memcmp(h, th, 32) != 0 || memcmp(S, tS, 65) != 0) {
            printf("sm9_sign_cases %d wrong signature\n", i+1);
            goto end;
        }

        if (SM9_verify(h, S, msg, strlen((char*)msg), id, strlen((char*)id), hid, master_pubkey) != GML_OK) {
            printf("sm9_sign_cases SM9_verify %d FAIL\n", i+1);
            goto end;
        }
    }

    printf("sm9_sign_cases PASS\n");
    ret = GML_OK;
end:
    return ret;
}

static void sm9_sign_test(void *p)
{
    int N;

    /* message */
    uint8_t msg[TEST_SM9_MSG_MAX_LENGTH];
    int msglen;

    /* id */
    uint8_t id[TEST_SM9_ID_MAX_LENGTH];
    int idlen;

    /* hid */
    uint8_t hid;

    /* h */
    uint8_t h[32];

    /* S */
    uint8_t S[65];

    /*  */
    uint8_t user_privkey[65];
    
    /*  */
    uint8_t master_privkey[32];

    /*  */
    uint8_t master_pubkey[129];

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N;

    for (int i = 0; i < N; i++) {
        /* random message */
        msglen = random_number() % TEST_SM9_MSG_MAX_LENGTH;
        random_string(msg, msglen);

        /* random id */
        idlen = random_number() % TEST_SM9_ID_MAX_LENGTH + 1;
        random_string(id, idlen);

        /* random hid, although hid ∈ {1, 2, 3} */
        hid = (uint8_t)(random_number() % 3 + 1);
        
        /* keygen */
        SM9_master_keygen(master_privkey, master_pubkey);
        SM9_usr_keygen(user_privkey, id, idlen, hid, master_privkey);

        /* sign */
        if (SM9_sign(h, S, msg, msglen, NULL, user_privkey, master_pubkey) != GML_OK) {
            print_hex("h:", h, 32);
            print_hex("S:", S, 65);
            print_hex("msg:", msg, msglen);
            print_hex("user_privkey:", user_privkey, 65);
            print_hex("master_pubkey:", master_pubkey, 129);
            printf("sm9 sign FAIL %d \n", i+1);
            args->ok = 0;
            return;
        }

        /* verify */
        if (SM9_verify(h, S, msg, msglen, id, idlen, hid, master_pubkey) != GML_OK) {
            print_hex("h:", h, 32);
            print_hex("S:", S, 65);
            print_hex("msg:", msg, msglen);
            print_hex("id:", id, idlen);
            print_hex("user_privkey:", user_privkey, 65);
            print_hex("master_pubkey:", master_pubkey, 129);
            printf("sm9 verify FAIL %d \n", i+1);
            args->ok = 0;
            return;
        }
    }

    printf("sm9 sign and verify PASS %d \n", N);
    args->ok = GML_OK;
}

int main(int argc, char **argv)
{
    int ret;
    if (CRYPTO_init() == GML_ERROR)
        return -1;

    TEST_ARGS args;
    args.ok = 0;
    args.N = 250;
    args.num_threads = 4;
    get_test_arg(argc, argv, &args);

    if (sm9_sign_cases() != GML_OK) return -1;

    printf("-----------SM9 HASH TEST------------ \n");
    sm9_H1_H2_test_case((void*)&args); if(args.ok == GML_ERROR) return -1;

    /* single thread test */
    printf("-----------SM9 SIGN VERIFY SINGLE THREAD TEST------------ \n");
    sm9_sign_test((void*)&args); if(args.ok == GML_ERROR) return -1;

    /* multi thread test */
    printf("\n-----------SM9 SIGN VERIFY MULTI THREAD TEST------------- \n");
    printf("number of threads : %ld \n\n", args.num_threads);
    ret = test_start_n_thread(sm9_sign_test, &args); if(ret == GML_ERROR) return -1;

    CRYPTO_deinit();
    return 0;
}