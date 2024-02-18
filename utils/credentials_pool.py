import sys, time, threading, random, datetime
from utils.cache import Cache
from queue import SimpleQueue


class User:
    def __init__(self, username, passwords = None):
        self.username = username
        self.duplicates_set = set()
        self.domain = CredentialsPool.get_user_domain(self.username)
        if type(passwords) == list:
            for p in passwords:
                if not p in self.duplicates_set:
                    self.passwords.put(p)
                    self.duplicates_set.add(p)
        elif type(passwords) == SimpleQueue:
            self.passwords = passwords
        else:
            self.passwords = SimpleQueue()
    
    def add_password(self, p):
        if not p in self.duplicates_set:
            self.passwords.put(p)
            self.duplicates_set.add(p)
    
    def add_passwords(self, L):
        for p in L:
            if not p in self.duplicates_set:
                self.passwords.put(p)
                self.duplicates_set.add(p)

    def get_next_password(self):
        if self.passwords.empty():
            return None
        p = None
        try:
            p = self.passwords.get_nowait()
        finally:
            return p
    
    @property
    def priority(self):
        return self.passwords.qsize()
    
    def __gt__(self, other):
        return self.priority > other.priority

    def __lt__(self, other):
        return self.priority < other.priority

    def __ge__(self, other):
        return self.priority >= other.priority

    def __le__(self, other):
        return self.priority <= other.priority
    
    def __eq__(self, other):
        return self.username == other.username
    
    def __hash__(self):
        return hash(self.username)
    
    def __repr__(self):
        ret = self.username + ":\n"
        l = self.passwords.qsize()
        for _ in range(l):
            p = self.passwords.get()
            ret += " "*4 + p + "\n"
            self.passwords.put(p)
        return ret
    
    def __str__(self):
        return self.__repr__()


class CredentialsPool:

    DELAY_INTERVALS = 2

    @staticmethod
    def ww_calc_next_spray_delay(offset):
        spray_times = [8,12,14] # launch sprays at 7AM, 11AM and 3PM (please do not put 11PM in there)

        now = datetime.datetime.utcnow() + datetime.timedelta(hours=offset)
        hour_cur = int(now.strftime("%H"))
        minutes_cur = int(now.strftime("%M"))
        day_cur = int(now.weekday())

        delay = 0

        # if just after the spray hour, use this time as the start and go
        if hour_cur in spray_times and day_cur <= 4:
            delay = 0
            return delay

        next = []

        # if it's Friday and it's after the last spray period
        if (day_cur == 4 and hour_cur > spray_times[-1]) or day_cur > 4:
            next = [0,0]
        elif hour_cur > spray_times[-1]:
            next = [day_cur+1, 0]
        else:
            for i in range(0,len(spray_times)):
                if spray_times[i] > hour_cur:
                    next = [day_cur, i]
                    break

        day_next = next[0]
        hour_next = spray_times[next[1]]

        if next == [0,0]:
            day_next = 7

        hd = hour_next - hour_cur
        md = 0 - minutes_cur
        if day_next == day_cur:
            delay = hd*60 + md
        else:
            dd = day_next - day_cur
            delay = dd*24*60 + hd*60 + md

        return delay*60

    @staticmethod
    def get_user_domain(u):
        return u.split("@")[-1]
    
    def cancellable_sleep(self, sec):
        # print("Starting sleep for", sec)
        delay_total = sec
        delay_turns = round(delay_total // CredentialsPool.DELAY_INTERVALS)
        for _ in range(delay_turns):
            if self.cancelled or len(self.pool.keys()) == 0:
                return
            time.sleep(CredentialsPool.DELAY_INTERVALS)
        if self.cancelled or len(self.pool.keys()) == 0:
                return
        time.sleep(delay_total % CredentialsPool.DELAY_INTERVALS)

    def __init__(self, users=set(), passwords={"default":set()}, userpass=[], useragents=None, delays={"var": 1, "req":1, "batch": 0, "domain":10, "user":100}, batch_size=1, weekday_warrior=None, cache=None, logger_entry=None, logger_success=None, signal_success=print):
        self.users = users
        self.passwords = passwords
        self.userpass = userpass
        self.useragents = useragents
        self.delays = delays
        self.batch_size = batch_size
        self.batch_count = 0
        self.cache = cache
        self.logger_entry = logger_entry
        self.logger_success = logger_success
        self.signal_success = signal_success
        self.weekday_warrior = weekday_warrior
        self.get_creds_lock = threading.Lock()
        self.cancelled = False
        self.attempts_total = 0
        self.attempts_count = 0
        self.attempts_trimmed = 0

        for delay_type in ['var', 'req', 'batch', 'domain', 'user']:
            if not delay_type in self.delays.keys() or self.delays[delay_type] is None:
                self.delays[delay_type] = 0
        
        self.ready = {"users": dict(), "domains": set()}
        # self.ready
        # ├── "domains"
        # │   └── set:[domain]
        # └── "users"
        #     └── set:[domain]
        #         └── set:[User]
        self.pool = dict()
        # self.pool
        # └── User

        self.cache = cache
        if self.cache is None:
            self.cache = Cache()
        
        if self.delays["batch"] is None:
            self.delays["batch"] = 0
        if self.batch_size is None:
            self.batch_size = 0
        
        cache_cursor = self.cache.get_cursor()

        for u,p in self.userpass:
            if not self.cache.user_exists(u, cache_cursor):
                # TODO signal hat user does not exist
                continue
            # if the user is not in the pool
            if not u in self.pool.keys():
                self.pool[u] = User(u)
            d = CredentialsPool.get_user_domain(u)
            # set the domain in the "ready" state
            if not d in self.ready["domains"]:
                self.ready["domains"].add(d)
            # set the user in the "ready" state
            if not d in self.ready["users"].keys():
                self.ready["users"][d] = set()
            self.ready["users"][d].add(u)

            user_success, password_success = self.cache.user_success(u)
            if user_success:
                logger_entry.info(f"Took from cache 1 : {u}:{password_success} - [+] SUCCESS !")
                logger_success.info(f"{u}:{password_success}")
                signal_success(u, password_success)
            else:
                crd = self.cache.query_creds(u, p, cache_cursor)
                if crd is None:
                    # print("Adding 1", f"{u}:{p}")
                    self.pool[u].add_password(p)
                else:
                    if crd[0] == Cache.RESULT_SUCCESS:
                        # Should not happen but meh
                        logger_entry.info(f"Took from cache: {u}:{p} - [+] SUCCESS !")
                        logger_success.info(f"{u}:{p}")
                        signal_success(u, p)
                    else:
                        logger_entry.info(f"Took from cache: {u}:{p} - {Cache.TRANSLATE_INV[crd[0]]}, {crd[1]}")

        for u in self.users:
            if not self.cache.user_exists(u, cache_cursor):
                # TODO signal that user does not exist
                continue
            passes = self.passwords["default"]
            d = CredentialsPool.get_user_domain(u)
            if d in self.passwords.keys():
                passes = self.passwords[d] + self.passwords["default"]
            
            if not u in self.pool.keys():
                self.pool[u] = User(u)
            
            # set the domain in the "ready" state
            if not d in self.ready["domains"]:
                self.ready["domains"].add(d)
            # set the user in the "ready" state
            if not d in self.ready["users"].keys():
                self.ready["users"][d] = set()
            self.ready["users"][d].add(u)
            
            user_success, password_success = self.cache.user_success(u)
            if user_success:
                logger_entry.info(f"Took from cache 4 : {u}:{password_success} - [+] SUCCESS !")
                logger_success.info(f"{u}:{password_success}")
                signal_success(u, password_success)
                self.trim_user(u)
            else:
                for p in passes:
                    if self.cache.user_exists(u, cache_cursor):
                        crd = self.cache.query_creds(u, p, cache_cursor)
                        if crd is None:
                            # print("Adding 2", f"{u}:{p}")
                            self.pool[u].add_password(p)
                        else:
                            if crd[0] == Cache.RESULT_SUCCESS:
                                # Should not happen, but meh
                                logger_entry.info(f"Took from cache: {u}:{p} - [+] SUCCESS !")
                                logger_success.info(f"{u}:{p}")
                                signal_success(u, p)
                            else:
                                logger_entry.info(f"Took from cache: {u}:{p} - {Cache.TRANSLATE_INV[crd[0]]}, {crd[1]}")
            # RAM optimization
            if u in self.pool.keys():
                del self.pool[u].duplicates_set
        
        # Count the total attempts for stats
        for u in self.pool.keys():
            self.attempts_total += self.pool[u].passwords.qsize()
        
        self.logger_entry.debug("POOL IS :")
        self.logger_entry.debug("".join([str(self.pool[u]) for u in self.pool]))

    def apply_delays(self, user):
        if self.cancelled or len(self.pool.keys()) == 0:
            return
        d = CredentialsPool.get_user_domain(user)
        thread_request = threading.Thread(target=self.per_request_delay_thread)
        thread_user = threading.Thread(target=self.delay_thread, args=("user", user))
        thread_domain = threading.Thread(target=self.delay_thread, args=("domain", user))
        thread_request.start()
        thread_user.start()
        thread_domain.start()
    
    def delay_thread(self, type, user):
        if self.cancelled or len(self.pool.keys()) == 0:
            return
        sleep_time = self.delays[type] + random.random()*self.delays["var"]
        # self.logger_entry.debug(f"Sleeping for {sleep_time} seconds ({type} delay)")
        self.cancellable_sleep(sleep_time)
        d = CredentialsPool.get_user_domain(user)
        if type == "domain":
            self.ready["domains"].add(d)
        elif type == "user" and user in self.pool.keys() and not self.pool[user].passwords.empty():
            self.ready["users"][d].add(user)
    
    def per_request_delay_thread(self):
        if len(self.pool.keys()) == 0 or self.cancelled:
            return
        if self.batch_size is not None and self.batch_size > 0:
            self.batch_count += 1
            if self.batch_count >= self.batch_size:
                self.batch_count = 0
                sleep_time = self.delays["batch"] + random.random()*self.delays["var"]
                self.logger_entry.debug(f"Sleeping {sleep_time} s because end of batch")
                self.cancellable_sleep(sleep_time)
        delay = self.delays["req"] + random.random()*self.delays["var"]
        # self.logger_entry.debug(f"Sleeping {delay} s between creds")
        self.cancellable_sleep(delay)

        if self.weekday_warrior is not None:
            delay = CredentialsPool.ww_calc_next_spray_delay(self.weekday_warrior)
            if delay > 0:
                next_time = datetime.datetime.utcnow() + datetime.timedelta(hours=self.weekday_warrior) + datetime.timedelta(seconds=delay)
                self.logger_entry.info(f"Sleeping until {str(next_time)} (ie. {delay} seconds) because of weekday warrior")
                self.cancellable_sleep(delay)
        try:
            # self.logger_entry.debug("Releasing lock")
            self.get_creds_lock.release()
        except Exception as ex:
            if 'unlocked lock' in str(ex):
                pass
            else:
                self.logger_entry.debug(f"EXCEPTION: {ex}")

    def get_creds(self):
        self.get_creds_lock.acquire()
        user_found = False
        while not user_found and len(self.pool.keys()) > 0 and not self.cancelled:
            username = ""
            candidate_found = False
            while not candidate_found and len(self.pool.keys()) > 0 and not self.cancelled:
                for d in list(self.ready["domains"]):
                    ready_users = [self.pool[u] for u in self.ready["users"][d]]
                    if len(ready_users) > 0:
                        candidate_found = True
                        # get the user with the most passwords left to try
                        candidate = max(ready_users)
                        if username != "":
                            candidate = max(candidate, self.pool[username])
                        username = candidate.username
                if not candidate_found and not self.cancelled:
                    # self.logger_entry.debug("No candidate, sleeping")
                    # self.logger_entry.debug(self.ready)
                    time.sleep(5)
            if self.cancelled:
                try:
                    # self.logger_entry.debug("Releasing lock")
                    self.get_creds_lock.release()
                except Exception as ex:
                    if 'unlocked lock' in str(ex):
                        pass
                    else:
                        self.logger_entry.debug(f"EXCEPTION3: {ex}")
                return None
            if username in self.pool.keys() and not self.pool[username].passwords.empty():
                user_found = True
            elif username in self.pool.keys():
                del self.pool[username]
            d = CredentialsPool.get_user_domain(username)
            self.ready["users"][d].remove(username)
            if user_found:
                self.ready["domains"].remove(CredentialsPool.get_user_domain(username))

        if self.cancelled or (not user_found and len(self.pool.keys()) == 0):
            # print("Releasing creds lock")
            try:
                # self.logger_entry.debug("Releasing lock")
                self.get_creds_lock.release()
            except Exception as ex:
                if 'unlocked lock' in str(ex):
                    pass
                else:
                    self.logger_entry.debug(f"EXCEPTION2: {ex}")
            return None

        password = self.pool[username].get_next_password()
        if self.pool[username].passwords.empty():
            del self.pool[username]
        
        self.apply_delays(username)
        self.attempts_count += 1
        return {"username": username, "password": password, "useragent": random.choice(list(self.useragents))}
        
    def trim_user(self, username):
        self.logger_entry.debug(f"Trimming {username}")
        if username in self.pool.keys():
            self.attempts_trimmed += self.pool[username].passwords.qsize()
            del self.pool[username]
            d = CredentialsPool.get_user_domain(username)
            if d in self.ready["users"].keys() and username in self.ready["users"][d]:
                self.ready["users"][d].remove(username)
    
    def creds_left(self):
        for u in self.pool.keys():
            if not self.pool[u].passwords.empty():
                return True
        return False