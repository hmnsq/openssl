/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#అన్తర్భావ "arch/loongarch_arch.h"

శూన్య sha256_ఖండం_దత్తాంశం_క్రమం_la64v100(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె);
శూన్య sha256_ఖండం_దత్తాంశం_క్రమం_lsx(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె);
శూన్య sha256_ఖండం_దత్తాంశం_క్రమం(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె);

శూన్య sha256_ఖండం_దత్తాంశం_క్రమం(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె)
{
    ఒకవేళ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_ఖండం_దత్తాంశం_క్రమం_lsx(ctx, లోపల, అంకె);
    } లేకపోతే {
        sha256_ఖండం_దత్తాంశం_క్రమం_la64v100(ctx, లోపల, అంకె);
    }
}

శూన్య sha512_ఖండం_దత్తాంశం_క్రమం_la64v100(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె);
శూన్య sha512_ఖండం_దత్తాంశం_క్రమం_lsx(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె);
శూన్య sha512_ఖండం_దత్తాంశం_క్రమం(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె);

శూన్య sha512_ఖండం_దత్తాంశం_క్రమం(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె)
{
    ఒకవేళ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_ఖండం_దత్తాంశం_క్రమం_lsx(ctx, లోపల, అంకె);
    } లేకపోతే {
        sha512_ఖండం_దత్తాంశం_క్రమం_la64v100(ctx, లోపల, అంకె);
    }
}
