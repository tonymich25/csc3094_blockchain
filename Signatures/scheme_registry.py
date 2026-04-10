from Signatures.ecdsa import ECDSASignature
from Signatures.eddsa import EdDSASignature
from Signatures.dilithium import DilithiumSignature
from Signatures.falcon import FalconSignature

scheme_registry = {
    ECDSASignature.NAME: ECDSASignature(),
    EdDSASignature.NAME: EdDSASignature(),
    DilithiumSignature.NAME: DilithiumSignature(),
    FalconSignature.NAME: FalconSignature(),
}