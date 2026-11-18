# RFC vectors provide independent expectations for Privacy Pass tests

The JSON fixtures copy hexadecimal fields from the RFCs so that tests can
check Freebird's output against independent expected values. Each field is
stored as continuous lowercase hex with RFC line wrapping removed.

| Fixture | Source | SHA-256 of downloaded RFC text | SHA-256 of fixture |
| --- | --- | --- | --- |
| `rfc9577-a1.json` | [RFC 9577 Appendix A.1](https://www.rfc-editor.org/rfc/rfc9577#appendix-A.1) | `cbd637959c3ed5b260fb38db525f39c3d228c90ff48af46b80dc1dbc9b3707b4` | `1c4c53541963640352dbf941ed913fad46a488b2ef62d9011233902e80cfe492` |
| `rfc9578-a2.json` | [RFC 9578 Appendix A.2](https://www.rfc-editor.org/rfc/rfc9578#appendix-A.2) | `bc3cb0d503f6998813ea6c9815031865beb255e00cb194d725a5c4012c3f2c83` | `94e26faf369c979f0aa5997784318c51318f1e23b0c874a9a2d183ff47f7e3ef` |

Use the published private keys in the RFC 9578 fixture only for
**conformance tests**. Never use them in a deployment. Use the reserved
greasing vector in the RFC 9577 fixture to test that the parser handles an
unsupported type. It is not a valid type-2 token.

The automated extraction checked five type-2 vectors for requests of 259
bytes, responses of 256 bytes, and tokens of 354 bytes. It also checked the
nonce and the bindings to the challenge and key through SHA-256. Compare
implementation output with the fixtures, and do not regenerate the expected
values from Freebird.

Copyright (c) 2024 IETF Trust and the persons identified as the document
authors. All rights reserved.

The extracted code components are distributed under the Revised BSD License
in the [IETF Trust Legal Provisions](https://trustee.ietf.org/license-info/).

> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions are met:
>
> 1. Redistributions of source code must retain the above copyright notice,
>    this list of conditions and the following disclaimer.
> 2. Redistributions in binary form must reproduce the above copyright notice,
>    this list of conditions and the following disclaimer in the documentation
>    and/or other materials provided with the distribution.
> 3. Neither the name of the IETF Trust nor the names of its contributors may
>    be used to endorse or promote products derived from this software without
>    specific prior written permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
> AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
> IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
> ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
> LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
> CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
> SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
> INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
> CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
> ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
> POSSIBILITY OF SUCH DAMAGE.
