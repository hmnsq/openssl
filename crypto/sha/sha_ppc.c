/*
 * Copyright 2009-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ <openssl/opensslconf.h>
#அந்தர்பாவ <openssl/sha.h>
#அந்தர்பாவ "arch/ppc_arch.h"

வெறுமை sha256_block_p8(வெறுமை *ctx, மாறிலி வெறுமை *inp, size_t len);
வெறுமை sha256_block_ppc(வெறுமை *ctx, மாறிலி வெறுமை *inp, size_t len);
வெறுமை sha256_block_data_order(வெறுமை *ctx, மாறிலி வெறுமை *inp, size_t len);
வெறுமை sha256_block_data_order(வெறுமை *ctx, மாறிலி வெறுமை *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_block_p8(ctx, inp, len) : sha256_block_ppc(ctx, inp, len);
}

வெறுமை sha512_block_p8(வெறுமை *ctx, மாறிலி வெறுமை *inp, size_t len);
வெறுமை sha512_block_ppc(வெறுமை *ctx, மாறிலி வெறுமை *inp, size_t len);
வெறுமை sha512_block_data_order(வெறுமை *ctx, மாறிலி வெறுமை *inp, size_t len);
வெறுமை sha512_block_data_order(வெறுமை *ctx, மாறிலி வெறுமை *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_block_p8(ctx, inp, len) : sha512_block_ppc(ctx, inp, len);
}
