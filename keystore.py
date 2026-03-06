class KeyStore:
    def __init__(self, scheme_registry):
        self.scheme_registry = scheme_registry
        self.keys = {}  # keys[sender_id][scheme_name] = {"sk":..., "pk":...}

    def ensure_sender_keys(self, sender_id, scheme_names):
        if sender_id not in self.keys:
            self.keys[sender_id] = {}

        for name in scheme_names:
            if name in self.keys[sender_id]:
                continue

            scheme = self.scheme_registry.get(name)
            if scheme is None:
                raise ValueError("Unknown scheme: " + str(name))

            sk, pk = scheme.generate_keypair()
            self.keys[sender_id][name] = {"sk": sk, "pk": pk}

    def get_keypair(self, sender_id, scheme_name):
        try:
            entry = self.keys[sender_id][scheme_name]
        except KeyError:
            raise ValueError("Missing keys for sender=" + str(sender_id) + " scheme=" + str(scheme_name))
        return entry["sk"], entry["pk"]

    def get_sk(self, sender_id, scheme_name):
        sk, _ = self.get_keypair(sender_id, scheme_name)
        return sk

    def get_pk(self, sender_id, scheme_name):
        _, pk = self.get_keypair(sender_id, scheme_name)
        return pk