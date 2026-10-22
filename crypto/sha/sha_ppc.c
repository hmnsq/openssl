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

शून्य sha256_खण्डम्_p8(शून्य *ctx, ध्रुव शून्य *inp, size_t len);
शून्य sha256_खण्डम्_ppc(शून्य *ctx, ध्रुव शून्य *inp, size_t len);
शून्य sha256_खण्डम्_दत्त_क्रमः(शून्य *ctx, ध्रुव शून्य *inp, size_t len);
शून्य sha256_खण्डम्_दत्त_क्रमः(शून्य *ctx, ध्रुव शून्य *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_खण्डम्_p8(ctx, inp, len) : sha256_खण्डम्_ppc(ctx, inp, len);
}

शून्य sha512_खण्डम्_p8(शून्य *ctx, ध्रुव शून्य *inp, size_t len);
शून्य sha512_खण्डम्_ppc(शून्य *ctx, ध्रुव शून्य *inp, size_t len);
शून्य sha512_खण्डम्_दत्त_क्रमः(शून्य *ctx, ध्रुव शून्य *inp, size_t len);
शून्य sha512_खण्डम्_दत्त_क्रमः(शून्य *ctx, ध्रुव शून्य *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_खण्डम्_p8(ctx, inp, len) : sha512_खण्डम्_ppc(ctx, inp, len);
}
