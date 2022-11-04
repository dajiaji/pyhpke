from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey


class TestSample:
    """
    Tests for sample code.
    """

    def test_hpke(self):

        # The sender side:
        suite_s = CipherSuite.new(KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)
        pkr = KEMKey.from_jwk(
            {
                "kty": "EC",
                "kid": "01",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            }
        )
        enc, sender = suite_s.create_sender_context(pkr)
        ct = sender.seal(b"Hello world!")

        # The recipient side:
        suite_r = CipherSuite.new(KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)
        skr = KEMKey.from_jwk(
            {
                "kty": "EC",
                "alg": "ECDH-ES+HKDF-256",
                "kid": "01",
                "crv": "P-256",
                "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
            }
        )
        recipient = suite_r.create_recipient_context(enc, skr)
        pt = recipient.open(ct)

        assert pt == b"Hello world!"
