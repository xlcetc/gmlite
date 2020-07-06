/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <gmlite/ec.h>
#include <gmlite/sm9.h>
#include "sm9_lcl.h"
#include "../ec/ec_lcl.h"
#include "../pairing/pairing_lcl.h"

const EC_GROUP *sm9_group = NULL;
const ATE_CTX *sm9_ate_ctx = NULL;

const EC_GROUP* SM9_get_group()
{
    if (sm9_group == NULL)
        return NULL;

    return sm9_group;
}

const ATE_CTX* SM9_get_pairing_ctx()
{
    if (sm9_ate_ctx == NULL)
        return NULL;

    return sm9_ate_ctx;
}

int sm9_group_init()
{
    sm9_group = EC_GROUP_new_sm9();
    return GML_OK;
}

int sm9_pairing_init()
{
    sm9_ate_ctx = PAIRING_init(SM9_T, SM9_P, SM9_N, SM9_B,
                SM9_G1X, SM9_G1Y, SM9_G2X, SM9_G2Y);

    if (sm9_ate_ctx == NULL)
        return GML_ERROR;
    
    return GML_OK;
}
