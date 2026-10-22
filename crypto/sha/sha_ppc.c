/*
 * Copyright 2009-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ <openssl/opensslconf.h>
#అన్తర్భావ <openssl/sha.h>
#అన్తర్భావ "arch/ppc_arch.h"

శూన్య sha256_ఖండం_p8(శూన్య *ctx, స్థిరరాశి శూన్య *inp, size_t len);
శూన్య sha256_ఖండం_ppc(శూన్య *ctx, స్థిరరాశి శూన్య *inp, size_t len);
శూన్య sha256_ఖండం_దత్తాంశం_క్రమం(శూన్య *ctx, స్థిరరాశి శూన్య *inp, size_t len);
శూన్య sha256_ఖండం_దత్తాంశం_క్రమం(శూన్య *ctx, స్థిరరాశి శూన్య *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_ఖండం_p8(ctx, inp, len) : sha256_ఖండం_ppc(ctx, inp, len);
}

శూన్య sha512_ఖండం_p8(శూన్య *ctx, స్థిరరాశి శూన్య *inp, size_t len);
శూన్య sha512_ఖండం_ppc(శూన్య *ctx, స్థిరరాశి శూన్య *inp, size_t len);
శూన్య sha512_ఖండం_దత్తాంశం_క్రమం(శూన్య *ctx, స్థిరరాశి శూన్య *inp, size_t len);
శూన్య sha512_ఖండం_దత్తాంశం_క్రమం(శూన్య *ctx, స్థిరరాశి శూన్య *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_ఖండం_p8(ctx, inp, len) : sha512_ఖండం_ppc(ctx, inp, len);
}
