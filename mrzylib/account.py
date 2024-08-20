from .loggermixin import LoggerMixin
from .modules import login

class MrzyAccount(LoggerMixin):
    _account_dict = {} # cache for username -> login obj

    def __new__(cls, username, password, *, auto_login=False):
        if (obj := cls._account_dict.get(username)) is not None:
            cls.debug("Found cache entry for user %s", username)
            if not obj.logged_on and auto_login:
                obj.login()

            return obj

        cls.debug("Didn't find cache entry for user %s", username)
        self = super().__new__(cls)
        self.username = username
        self.password = password
        self.logged_on = False
        self.token = None
        self.open_id = None

        if auto_login:
            self.login()

        return self

    def login(self):
        self.info("Logging in...")
        json = login.Login(
            login=self.username,
            password=self.password
        ).exec()
        self.token = json["data"]["token"]
        self.open_id = json["data"]["openId"]
        self.info("Logged in.")

        self.debug("User Token: %s", self.token)
        self.debug("User Open ID: %s", self.open_id)
