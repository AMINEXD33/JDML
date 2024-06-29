import logging
import threading
from jwt_impl import JWT_IMP
import json
import datetime
from datetime import timedelta
import time


# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(threadName)s] %(levelname)s: %(message)s",
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()],
)


class ThreadRoutine:
    def __init__(self, id):
        self.jwt_reference = JWT_IMP()
        self.id = id

    """
    got an idea to log the keys when a specific time is met, to see 
    if all workers synced the keys correctly 
    """

    def return_public_pricate_json(self):
        """
        just return the private and public keys json
        """
        json_private = "private::>" + self.jwt_reference.keys.private_key.export()
        json_public = "public ::>" + self.jwt_reference.keys.public_key.export_public()
        return str(json_private) + "\n" + str(json_public)

    def driver_function_(self):
        """
        this function is meant to execute the await_time function
        """
        day_, min_, sec_ = self.current_time()
        print("passed:", day_, min_, sec_)
        target_time = timedelta(days=day_, minutes=min_, seconds=sec_) + timedelta(
            seconds=15
        )
        self.await_time(target_time, self.return_public_pricate_json)

    def in_other_thread(self):
        """
        to not interfear with any running code, we can just run this
        process in an other thread
        """
        thread__ = threading.Thread(target=self.driver_function_)
        thread__.start()
        thread__.join()

    """"""

    def refresh_keys_same_instance(self):
        pairs = self.jwt_reference.keys.generate_new_pairs()
        self.jwt_reference.SubPubManager.update_and_publish(
            pairs["private_key"], pairs["public_key"]
        )
        logging.debug(f"Thread {self.id}: Refreshed keys and published updates")

    def routine1(self):
        logging.debug(f"Thread {self.id}: Starting routine 1")
        self.refresh_keys_same_instance()
        tok, expdate = self.jwt_reference.TokenManager.make_configured_token("amine", "meftah", {"id":14124, "admin":True})
        print(f'TREAD {self.id}managed to decrypt> , ', self.jwt_reference.decr_token(tok).claims)
        logging.debug(f"Thread {self.id}: Completed routine 1")


if __name__ == "__main__":
    test_threads_target = 48
    thread_routines = []

    # Create instances of ThreadRoutine
    for x in range(test_threads_target):
        thread_routines.append(ThreadRoutine(x))

    threads = []

    # Create threads with corresponding ThreadRoutine targets
    for x in range(test_threads_target):
        threads.append(
            threading.Thread(target=thread_routines[x].routine1(), name=f"thread-{x}")
        )

    # Start all threads
    for thread in threads:
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()
