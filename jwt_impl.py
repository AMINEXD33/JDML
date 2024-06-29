import time
import random
import jwcrypto
import redis
from .redis_server_conf import custom_redis
from .keys import Keys
from .subpub import Sub_Pub_manager
import threading
import uuid
from jwcrypto import jwt, jwk, jwe
from jwcrypto.common import json_encode, json_decode
import json
from jwt_multi_workers.token_manager import Token_manager


class PrivateOrPublicKeyAreNull(Exception):
    def __init__(self):
        return "private key or public key are None"


class JWT_IMP:
    """JWT_IMP
    this module contains all classes that are responsible for implimenting the JWT_IMP
    authentication
    """

    def __init__(self):
        self.Redis = custom_redis().conn  # redis connection
        self.keys = Keys(self.Redis)  # the keypair instance
        self.SubPubManager = Sub_Pub_manager(self)
        self.TokenManager = Token_manager(self)

    def sync_keys(self):
        """
        this function will check if the key pair are still None
        if so that means that we didn't yet generated any keys for
        this instance , so we need first to check if the keys exist
        in redis , if so we just update this key pair to reflect that
        if not  we need to generate the new keys, then
        update redis, the sub pub manager will take care of the rest
        wich is notifying every worker including this one that
        the keys has changed, so they can change their instances.
        """
        # check redis for keys
        key_pair_dicts = self.keys.get_pair()
        if key_pair_dicts is not None:
            # keys already in redis
            # we need to update the attributes of
            # our keys
            self.keys.from_json(
                key_pair_dicts["private_key"], key_pair_dicts["public_key"]
            )
            return
        # keys are not in redis
        # generate new pair
        new_pair = self.keys.generate_new_pairs()
        # update the redis
        # meaning we triggered a new event
        """be careful not to switch the the vars"""
        self.SubPubManager.update_and_publish(
            new_pair["private_key"], new_pair["public_key"]
        )

    def refresh_keys(self):
        """
            this function refresh the keys
        """
        # keys are not in redis
        # generate new pair
        new_pair = self.keys.generate_new_pairs()
        # update the redis
        # meaning we triggered a new event
        """be careful not to switch the the vars"""
        self.SubPubManager.update_and_publish(
            new_pair["private_key"], new_pair["public_key"]
        )

    def make_token(self, **claims):
        """
        this function takes a dict (claims) that containes all your data
        and for safty , a random and useless uuid will be inluded to make sure that the
        token is unique
        Return: encrypted token (string)
        """
        useless = str(uuid.uuid4())
        claims["useless"] = useless
        token = jwt.JWT(header={"alg": "RS256"}, claims=claims)
        type_ = type(self.keys.private_key)
        token.make_signed_token(self.keys.private_key)
        signed_token = token.serialize()

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
        this function takes an encrypted token and decrypt it 
        Return: decrypted token ot None if an error accured,
        """
        try:
            # Decrypt the JWT
            jwetoken = jwe.JWE()
            jwetoken.deserialize(encrypted_token, key=self.keys.private_key)
            signed_token_decrypted = jwetoken.payload.decode("utf-8")

            # Verify the signed JWT
            token = jwt.JWT(key=self.keys.public_key, jwt=signed_token_decrypted)
            # print("Decrypted and Verified Claims:", token.claims)
            return token
        except:
            return None
