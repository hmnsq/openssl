/*
 * Copyright 2009-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव <openssl/opensslconf.h>
#अन्तर्भाव <openssl/sha.h>
#अन्तर्भाव "arch/ppc_arch.h"

शून्य sha256_block_p8(शून्य *ctx, अचर शून्य *inp, माप_प्रकार len);
शून्य sha256_block_ppc(शून्य *ctx, अचर शून्य *inp, माप_प्रकार len);
शून्य sha256_block_data_order(शून्य *ctx, अचर शून्य *inp, माप_प्रकार len);
शून्य sha256_block_data_order(शून्य *ctx, अचर शून्य *inp, माप_प्रकार len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_block_p8(ctx, inp, len) : sha256_block_ppc(ctx, inp, len);
}

शून्य sha512_block_p8(शून्य *ctx, अचर शून्य *inp, माप_प्रकार len);
शून्य sha512_block_ppc(शून्य *ctx, अचर शून्य *inp, माप_प्रकार len);
शून्य sha512_block_data_order(शून्य *ctx, अचर शून्य *inp, माप_प्रकार len);
शून्य sha512_block_data_order(शून्य *ctx, अचर शून्य *inp, माप_प्रकार len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_block_p8(ctx, inp, len) : sha512_block_ppc(ctx, inp, len);
}
