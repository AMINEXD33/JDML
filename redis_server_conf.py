import redis


class custom_redis:
    """
    just a class to connect to the redis server
    """

    __HOST = "localhost"
    __PORT = "6379"

    def __init__(self):
        self.conn = redis.Redis(
            host=custom_redis.__HOST, port=custom_redis.__PORT, decode_responses=True
        )
