import time
import random
import jwcrypto
import redis
from redis_server_conf import custom_redis
from keys import Keys
from subpub import Sub_Pub_manager
import threading
import uuid
from jwcrypto import jwt, jwk, jwe
from jwcrypto.common import json_encode, json_decode
import json
from token_manager import Token_manager


class PrivateOrPublicKeyAreNull(Exception):
    def __init__(self):
        return "private key or public key are None"


class JWT_IMP:
    """JWT_IMP
    This module contains all classes that are responsible for 
    implementing the jwt authentication using RSA
    """

    def __init__(self):
        self.Redis = custom_redis().conn  # redis connection
        self.keys = Keys(self.Redis)  # the keypair instance
        self.SubPubManager = Sub_Pub_manager(self)
        self.TokenManager = Token_manager(self)

    def sync_keys(self):
        """
        This function checks if the key pair is still `None`. 
        If so, it means that we haven't generated any keys for 
        this instance yet. Therefore, we first need to check if the 
        keys exist in Redis. If they do, we update this key pair accordingly. 
        If not, we need to generate new keys and then update Redis. 
        The pub/sub manager will handle notifying every worker, 
        including this one, that the keys have changed so they can update 
        their instances.
        """
        #Check Redis for keys.
        key_pair_dicts = self.keys.get_pair()
        if key_pair_dicts is not None:
            # keys already in Redis
            #We need to update the attributes of
            # our keys
            self.keys.from_json(
                key_pair_dicts["private_key"], key_pair_dicts["public_key"]
            )
            return
        # keys are not in redis
        # generate a new pair
        new_pair = self.keys.generate_new_pairs()
        # update the redis
        # means we triggered a new event.
        """Be careful not to switch the variables."""
        self.SubPubManager.update_and_publish(
            new_pair["private_key"], new_pair["public_key"]
        )

    def refresh_keys(self):
        """
            This function refreshes the keys.
        """
        # keys are not in redis
        # generate a new pair
        new_pair = self.keys.generate_new_pairs()
        # update redis
        # meaning we triggered a new event.
        """Be careful not to switch the variables."""
        self.SubPubManager.update_and_publish(
            new_pair["private_key"], new_pair["public_key"]
        )

    def make_token(self, **claims):
        """
        This function takes a dict (claims) that contains all your data.
        And for safety, a random and useless ID will be included to make sure that the token is unique.
        Return: encrypted token (string)
        """
        useless = str(uuid.uuid4())
        claims["useless"] = useless
        token = jwt.JWT(header={"alg": "RS256"}, claims=claims)
        token.make_signed_token(self.keys.private_key)
        signed_token = token.serialize()

        # the protected header can be modified if needed
        protected_header = {
            "alg": "RSA-OAEP-256",
            "enc": "A256CBC-HS512",
            "typ": "JWE",
            "kid": self.keys.public_key.thumbprint(),
        }
        jwetoken = jwe.JWE(
            signed_token.encode("utf-8"),
            recipient=self.keys.public_key,
            protected=protected_header,
        )
        encrypted_token = jwetoken.serialize()
        return encrypted_token

    def decr_token(self, encrypted_token):
        """
        This function takes an encrypted token and decrypts it.
        Return: decrypted token or None if an error occurred.
        """
        try:
            # Decrypt the JWT
            jwetoken = jwe.JWE()
            jwetoken.deserialize(encrypted_token, key=self.keys.private_key)
            signed_token_decrypted = jwetoken.payload.decode("utf-8")
            # Verify the signed JWT.
            token = jwt.JWT(key=self.keys.public_key, jwt=signed_token_decrypted)
            return token
        except:
            return None
