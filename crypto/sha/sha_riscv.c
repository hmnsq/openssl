/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#అన్తర్భావ "arch/riscv_arch.h"

శూన్య sha256_ఖండం_దత్తాంశం_క్రమం_zvkb_zvknha_or_zvknhb(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల,
    size_t అంకె);
శూన్య sha256_ఖండం_దత్తాంశం_క్రమం_zbb(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె);
శూన్య sha256_ఖండం_దత్తాంశం_క్రమం_riscv64(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె);
శూన్య sha256_ఖండం_దత్తాంశం_క్రమం(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె);

శూన్య sha256_ఖండం_దత్తాంశం_క్రమం(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె)
{
    ఒకవేళ (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_ఖండం_దత్తాంశం_క్రమం_zvkb_zvknha_or_zvknhb(ctx, లోపల, అంకె);
    } లేకపోతే ఒకవేళ (RISCV_HAS_ZBB()) {
        sha256_ఖండం_దత్తాంశం_క్రమం_zbb(ctx, లోపల, అంకె);
    } లేకపోతే {
        sha256_ఖండం_దత్తాంశం_క్రమం_riscv64(ctx, లోపల, అంకె);
    }
}

శూన్య sha512_ఖండం_దత్తాంశం_క్రమం_zvkb_zvknhb(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె);
శూన్య sha512_ఖండం_దత్తాంశం_క్రమం_zbb(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె);
శూన్య sha512_ఖండం_దత్తాంశం_క్రమం_c(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె);
శూన్య sha512_ఖండం_దత్తాంశం_క్రమం(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె);

శూన్య sha512_ఖండం_దత్తాంశం_క్రమం(శూన్య *ctx, స్థిరరాశి శూన్య *లోపల, size_t అంకె)
{
    ఒకవేళ (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_ఖండం_దత్తాంశం_క్రమం_zvkb_zvknhb(ctx, లోపల, అంకె);
    } లేకపోతే ఒకవేళ (RISCV_HAS_ZBB()) {
        sha512_ఖండం_దత్తాంశం_క్రమం_zbb(ctx, లోపల, అంకె);
    } లేకపోతే {
        sha512_ఖండం_దత్తాంశం_క్రమం_c(ctx, లోపల, అంకె);
    }
}
