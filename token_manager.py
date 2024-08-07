import datetime
from datetime import timedelta
import json
import hashlib


class Token_manager:

    __CALLS_TO_CHANGE_KEYS = 10000  # the number of calls to rortate the keys
    __ALLOW_CACHING = True
    __CALLS = 0  # an instance tracker
    __EXPIRED_AFTER = 1  # days
    __BLACK_LIST_NAME = "bllist"  # the name of the black hash set in redis
    __CACHING_LIST_NAME = "tkcach"  # the name of the caching hash set in redis
    __PROVIDER = "TEST"  # added to the jwt

    def __init__(self, jwt_impl_reference):
        # reference of the JWT_IMP , jwt_impl.py
        self.jwt_impl = jwt_impl_reference
        # the name of the lock for the blacklist
        self.lock_key = "blacklist_lock/zd14sfd"
        # the name of the lock for caching
        self.lock_key2 = "caching_lock/afafgaf"
        # the name of the counter
        self.lock_count = "calls_counter"

    def to_sha_256(self, jwt_token: str):
        """
        hash jwt_token to an sha256
        """
        try:
            hashed = hashlib.sha256(jwt_token.encode("utf-8")).hexdigest()
            return hashed
        except Exception as e:
            print("hashing error", e)
            return None

    """token configuration methods"""

    def configure_token(self, token: dict):
        """
        this function get's a token , and configures it based on the
        attributes of the class
        """
        # calculate expiration data
        current_date = datetime.datetime.now()
        expiration_date = current_date + timedelta(
            days=Token_manager.__EXPIRED_AFTER
        )  ### REFACTOR TO DAYS !!!!
        expiration_date = expiration_date.strftime("%Y/%m/%d %H:%M:%S")
        # attach the new values
        token["provider"] = Token_manager.__PROVIDER
        token["expiration_date"] = expiration_date
        # we return the token and it's expiration date
        return token, expiration_date

    def make_configured_token(self, username: str, password: str, claims: dict):
        """
        this function takes the claims configures them then encrypt them
        using the jwt_impl.make_token function
        Return: encrypted_token(str), expiration_date(str)
        """
        # check count calls
        if Token_manager.__CALLS >= Token_manager.__CALLS_TO_CHANGE_KEYS:
            # if we reached the call limit
            self.safe_reload()  # reset the encryption keys , cache set , balacklist set
            Token_manager.__CALLS = 0  # reset calls

        configured_claims, expiration_date = self.configure_token(claims)
        encrypted_token = self.jwt_impl.make_token(**configured_claims)
        Token_manager.__CALLS += 1
        # after making the token , we can cache it
        if Token_manager.__ALLOW_CACHING:
            self.cash_token(username, password, encrypted_token)
        return encrypted_token, expiration_date

    """locks methods"""

    def acquire_lock(self, lock_number, timeout=100, retry=0.05):
        """
        This function acquires a lock for a transaction in Redis.
        The lock_number specifies if the function should acquire
        the lock for the blacklist (1) or caching (2)
        """
        lock = None
        if lock_number == 1:
            lock = self.lock_key
        elif lock_number == 2:
            lock = self.lock_key2
        while not self.jwt_impl.Redis.set(lock, "locked", nx=True, ex=timeout):
            time.sleep(retry)  # Retry every 50ms

    def release_lock(self, lock_number):
        """
        This function releases the lock in Redis.
        The lock_number specifies if the function should release.
        the lock for the blacklist (1) or caching (2)
        """
        lock = None
        if lock_number == 1:
            lock = self.lock_key
        else:
            lock = self.lock_key2
        self.jwt_impl.Redis.delete(lock)

    """blacklist methods"""

    def add_to_blacklist(self, token: str):
        """
        This function hashes the token and adds it to the blacklist.
        to confirm memory
        """

        with self.jwt_impl.Redis.pipeline() as pip:
            try:
                self.acquire_lock(1)
                pip.multi()
                self.jwt_impl.Redis.hset(
                    Token_manager.__BLACK_LIST_NAME, self.to_sha_256(token), ""
                )
                pip.execute()
                # print("added tp black list")
            except:
                pass
            finally:
                self.release_lock(1)

    def remove_from_blacklist(self, token: str):
        """
        this function removes a token from the black list using a locked transaction
        Params:
            token -> the target token
        """
        with self.jwt_impl.Redis.pipeline() as pip:
            try:
                self.acquire_lock(1)
                pip.multi()
                self.jwt_impl.Redis.hdel(
                    Token_manager.__BLACK_LIST_NAME, self.to_sha_256(token)
                )
                pip.execute()
                # print("removed black list")
            except:
                pass
            finally:
                self.release_lock(1)

    def is_black_listed(self, token: str):
        """
        this function checks if a token is black listed
        Return : true or false
        """
        token = self.jwt_impl.Redis.hget(
            Token_manager.__BLACK_LIST_NAME, self.to_sha_256(token)
        )
        # sinse we've used "" for the value of the key, we can't compair using == since it will always
        # return False
        if token != None:
            # print("it is blacklisted")
            return True
        return False

    def reset_black_list(self):
        """
        this function locks the blacklist and reset it
        deleting all old values
        """
        with self.jwt_impl.Redis.pipeline() as pip:
            try:
                self.acquire_lock(1)
                pip.multi()
                self.jwt_impl.Redis.delete(Token_manager.__BLACK_LIST_NAME)
                pip.execute()
                # print("black list reseted")
            except:
                pass
            finally:
                self.release_lock(1)

    """caching methods"""

    def cash_token(self, username: str, password: str, token: str):
        """
        this function cahches a token in a locked transaction
        """
        with self.jwt_impl.Redis.pipeline() as pip:
            try:
                self.acquire_lock(2)
                pip.multi()
                self.jwt_impl.Redis.hset(
                    Token_manager.__CACHING_LIST_NAME, username + password, token
                )
                pip.execute()
                print("cached successfully")
            except:
                pass
            finally:
                self.release_lock(2)

    def uncash_token(self, username: str, password: str):
        """
        this function removes a cached token in a locked transaction
        """
        with self.jwt_impl.Redis.pipeline() as pip:
            try:
                self.acquire_lock(2)
                pip.multi()
                self.jwt_impl.Redis.hdel(
                    Token_manager.__CACHING_LIST_NAME, username + password
                )
                pip.execute()
                # print("uncached successfully")
            except:
                pass
            finally:
                self.release_lock(2)

    def is_cached(self, username: str, password: str):
        """
        this function checks if a token is cached or not
        Return: the token  or false
        """
        cached = self.jwt_impl.Redis.hget(
            Token_manager.__CACHING_LIST_NAME, username + password
        )
        if cached:
            return cached
        else:
            return False

    def reset_cache(self):
        """
        this function resets the cache set
        deleting all values
        """
        with self.jwt_impl.Redis.pipeline() as pip:
            try:
                self.acquire_lock(2)
                pip.multi()
                self.jwt_impl.Redis.delete(Token_manager.__CACHING_LIST_NAME)
                pip.execute()
                # print("reseted cach")
            except:
                pass
            finally:
                self.release_lock(2)

    """token expiration methods"""

    # def figure_token(self, username: str, password: str, token: str):
    #     """
    #     this function
    #     """
    #     key = username + password
    #     decrypted_tok = self.jwt_impl.decr_token(token)
    #     current_date = datetime.datetime.now()
    #     if current_date >= decrypted_tok["expiration_date"]:
    #         # this token is not valid anymore , we can black list it
    #         self.add_to_blacklist(token)
    #         # print("figure_token")
    #         return False
    #     # still a valid token
    #     return True

    """on calls limit reached"""

    def safe_reload(self):
        """
        this function calles all the safe resets
        and then sync keys(rotate keys)
        """
        try:
            self.reset_black_list()
            self.reset_cache()
            self.jwt_impl.keys.remove_pair()
            self.jwt_impl.sync_keys()
            # print("safe reload done")
        except Exception as e:
            print("safe reload error", e)

    """abstraction to validate the token"""

    def abstract_token_validation(self, token: str):
        """
        This function will validate the giving token by checking the blacklist.
        and then try and decrypt it, finally checking the expiration date.
        Return: if the token is good (true), an invalid token (false).
        """
        # check if token is black listed
        if self.is_black_listed(token):
            return False
        # decrypt token
        dec_tok = None
        try:
            dec_tok = json.loads(self.jwt_impl.decr_token(token).claims)
        except:
            return False
        # check if token is expired
        expiration_date_str = dec_tok["expiration_date"]
        current_date = datetime.datetime.now()
        expiration_date_obj = datetime.datetime.strptime(
            expiration_date_str, "%Y/%m/%d %H:%M:%S"
        )
        if current_date >= expiration_date_obj:
            self.add_to_blacklist(token)
            return False
        return dec_tok

    def abstract_token_validation_get_reqs(self, username: str, password: str):
        """
        This function is meant to be used in the context of an authentication request, when the user sends
        a username or email and a password, it checks if a token is cached, and if so, it will check the validity of
        If it's valid, it will return the token
        return: if valid (token, expired_date), if not valid (false, none)
        """
        # check if the token is cached
        cached = self.is_cached(username, password)
        if not cached:
            # not cached
            return (False, None)
        # if it's blacklisted it needs to be removed from cach
        if self.is_black_listed(cached):
            self.uncash_token(username, password)
            return (False, None)
        # try do decrypt the token
        dec_tok = None
        try:
            dec_tok = json.loads(self.jwt_impl.decr_token(cached).claims)
        except:
            return (False, None)
        expiration_date = dec_tok["expiration_date"]
        # is the token expired
        current_datetime = datetime.datetime.now()
        expiration_date_parsed = datetime.datetime.strptime(
            expiration_date, "%Y/%m/%d %H:%M:%S"
        )
        if current_datetime >= expiration_date_parsed:
            return (False, None)
        # the token then must be valid
        # print("from cache")
        return (cached, expiration_date)
