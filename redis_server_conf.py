import redis


class custom_redis:
    """
    just a class to connect to redis server
    """

    # you can change the host and port as needed
    __HOST = "localhost"
    __PORT = "6379"

    def __init__(self):
        self.conn = redis.Redis(
            host=custom_redis.__HOST, port=custom_redis.__PORT, decode_responses=True
        )
