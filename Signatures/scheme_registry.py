from Signatures.dilithium import DilithiumSignature
from Signatures.ecdsa import ECDSASignature

scheme_registry = {
    ECDSASignature.NAME: ECDSASignature(),
    DilithiumSignature.NAME: DilithiumSignature(),
}

print(scheme_registry.keys())
print(ECDSASignature.NAME, DilithiumSignature.NAME)