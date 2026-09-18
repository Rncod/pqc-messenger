# crypto/signature.py

"""
Signatures post-quantiques basées sur CRYSTALS-Dilithium
via la librairie `dilithium-py`.

On utilise le niveau de sécurité Dilithium2 :
    from dilithium_py.dilithium import Dilithium2
"""

from dilithium_py.dilithium import Dilithium2


class ClientSigner:
    """
    Gestion des signatures côté CLIENT (Dilithium2).

    - génère une paire de clés (pk, sk)
    - expose pk au serveur
    - signe les messages avec sk
    """

    def __init__(self) -> None:
        # keygen() retourne (pk, sk) bit-packés
        self._pk, self._sk = Dilithium2.keygen()

    @property
    def public_key(self) -> bytes:
        """Clé publique du client à envoyer au serveur."""
        return self._pk

    def sign(self, data: bytes) -> bytes:
        """Signe les données avec la clé secrète Dilithium2."""
        return Dilithium2.sign(self._sk, data)


def verify_signature(client_public_key: bytes, data: bytes, signature: bytes) -> bool:
    """
    Vérifie la signature Dilithium2 côté serveur.
    Retourne True si la signature est valide, False sinon.
    """
    try:
        return bool(Dilithium2.verify(client_public_key, data, signature))
    except Exception:
        return False
