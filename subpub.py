import redis
import threading
import uuid
from jwcrypto import jwk
import json


#
class Sub_Pub_manager:
    """
    this class provides a way so every worker in any wsgi application, to be able to subscribe
    to a redis event chanel, so when a new encryption key pair are updated every worker will
    be notified and can update their coresponding keys as needed making the whole process(authenticating users)
    more scalable.
    """

    __FLAG_CHANNEL = "key_pair_updates"  # this is the name of the chanel that we will subscribe to (can be changed)

    def __init__(self, JWT_implim_instance):
        self.JWT_instance = (
            JWT_implim_instance  # JWT_IMP instance (see class in  JWT_impl.py)
        )
        self.redis_instance = self.JWT_instance.Redis  # redis connection instance
        # make a new thread with that subscribes to the __FLAG_CHANNEL redis channel
        upd_thread = threading.Thread(target=self.__listin_for_flag_updates)
        upd_thread.start()

    def __listin_for_flag_updates(self):
        """
        this function subsribes to the __FLAG_CHANNEL channel in redis, and listenes to
        any update that can happen, if an even is triggered a flag will be set for this JWT_IMP instance
        and the update_key_from_redis function from the JWT_instance is executed to update the keys and
        the flag for the worker runing this instance
        """

        def helper_extract_two_keys(new_key_pair_json_message):
            keys_dict = json.loads(new_key_pair_json_message["data"])
            # print("data+++++>>>>> ", keys_dict)
            return keys_dict

        flag_listiner = self.redis_instance.pubsub(ignore_subscribe_messages=True)
        flag_listiner.subscribe(Sub_Pub_manager.__FLAG_CHANNEL)
        # the flag is the new flag
        for new_key_pair_json_message in flag_listiner.listen():
            # print("the redis even got triggered !")
            extracted_keys = helper_extract_two_keys(new_key_pair_json_message)
            private_key = extracted_keys["private_key"]
            public_key = extracted_keys["public_key"]


            print(private_key == public_key)
            self.JWT_instance.keys.from_json(private_key, public_key)
            # print("loaded from chanell")

    def update_and_publish(self, private_key: object, public_key: object):
        """
        this function takes the new generated private and public keys
        triggeres a new event containing the pair , then updates the redis
        """
        # publish the new pairs
        ### CONTINUE
        # print("WEIIIIRD ", type(private_key), type(public_key))
        private_key_json = private_key.export()  # this is a json
        public_key_json = public_key.export_public()  # this is a json
        # print("update_and_pub, ", private_key == public_key)
        # Combine keys into a single JSON object
        key_pair = {
            "private_key": json.loads(private_key_json),
            "public_key": json.loads(public_key_json),
        }
        # jsonify it
        new_key_pair_json_message = json.dumps(key_pair)
        # publish new pair
        self.redis_instance.publish(
            Sub_Pub_manager.__FLAG_CHANNEL, new_key_pair_json_message
        )
        # print("new pair published")
        # update redis
        self.JWT_instance.keys.set_pair_into_redis(public_key, private_key)

    def __generate_new_flag(self):
        """
        Generate a new flag
        """
        return str(uuid.uuid4())
