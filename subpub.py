import redis
import threading
import uuid
from jwcrypto import jwk
import json


#
class Sub_Pub_manager:
    """
    This class provides a way for every worker in any WSGI application to be able to subscribe.
    to a redis event channel, so when a new encryption key pair is updated, every worker will
    be notified and can update their coresponding keys as needed, making the whole process (authenticating users)
    more scalable.
    """
    __FLAG_CHANNEL = "key_pair_updates"  # This is the name of the channel that we will subscribe to (it can be changed).
    def __init__(self, JWT_implim_instance):
        self.JWT_instance = (
            JWT_implim_instance  # JWT_IMP instance (see class in  JWT_impl.py)
        )
        self.redis_instance = self.JWT_instance.Redis  # redis connection instance
        # in a new thread subscribes to the __FLAG_CHANNEL redis channel
        upd_thread = threading.Thread(target=self.__listin_for_flag_updates)
        upd_thread.start()

    def __listin_for_flag_updates(self):
        """
        This function subscribes to the __FLAG_CHANNEL channel in Redis and listens to
        any update that can happen, if an event is triggered, a flag will be set for this JWT_IMP instance.
        and the update_key_from_redis function from the JWT_instance is executed to update the keys and
        the flag for the worker running this instance
        """

        def helper_extract_two_keys(new_key_pair_json_message):
            keys_dict = json.loads(new_key_pair_json_message["data"])
            return keys_dict

        flag_listiner = self.redis_instance.pubsub(ignore_subscribe_messages=True)
        flag_listiner.subscribe(Sub_Pub_manager.__FLAG_CHANNEL)
        # we're expecting one message(keys)
        for new_key_pair_json_message in flag_listiner.listen():
            extracted_keys = helper_extract_two_keys(new_key_pair_json_message)
            private_key = extracted_keys["private_key"]
            public_key = extracted_keys["public_key"]
            # load the keys
            self.JWT_instance.keys.from_json(private_key, public_key)

    def update_and_publish(self, private_key: object, public_key: object):
        """
        This function takes the newly generated private and public keys.
        triggers a new event containing the pair, then updates the redis
        """
        # publish the new pairs
        private_key_json = private_key.export()  # this is a json
        public_key_json = public_key.export_public()  # this is a json
        # Combine keys into an object
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
        # update redis
        self.JWT_instance.keys.set_pair_into_redis(public_key, private_key)
