from Signatures.ecdsa import ECDSASignature
from Signatures.dilithium import DilithiumSignature
from Signatures.falcon import FalconSignature

scheme_registry = {
    ECDSASignature.NAME: ECDSASignature(),
    DilithiumSignature.NAME: DilithiumSignature(),
    FalconSignature.NAME: FalconSignature(),
}