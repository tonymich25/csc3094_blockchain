from Signatures.dilithium import DilithiumSignature
from Signatures.ecdsa import ECDSASignature

scheme_registry = {
    ECDSASignature.NAME: ECDSASignature(),
    DilithiumSignature.NAME: DilithiumSignature(),
}