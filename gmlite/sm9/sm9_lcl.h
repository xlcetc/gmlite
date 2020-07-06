/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef HEADER_SM9_LCL_H
#define HEADER_SM9_LCL_H

#include <gmlite/ec.h>
#include <gmlite/pairing.h>

#define SM9_T "600000000058f98a"
#define SM9_P "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D"
#define SM9_N "B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25" // order
#define SM9_B "05"
// G1 generator
#define SM9_G1X "93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD"
#define SM9_G1Y "21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616"
// G2 generator
#define SM9_G2X "85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141", "3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b"  //--
#define SM9_G2Y "17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96", "a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7"  //--

/* sm9 group */
extern const EC_GROUP *sm9_group;
/* sm9 pairing context */
extern const ATE_CTX *sm9_ate_ctx;

int sm9_group_init();

int sm9_pairing_init();

int sm9_H1(BIGNUM *h, const uint8_t *a, int alen, const uint8_t *b, int blen, const BIGNUM *n);

int sm9_H2(BIGNUM *h, const uint8_t *a, int alen, const uint8_t *b, int blen, const BIGNUM *n);

#define SM9_HID_SIGN  0x01
#define SM9_HID_EXCH  0x02
#define SM9_HID_ENC   0x03

#endif