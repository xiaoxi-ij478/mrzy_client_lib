from abc import ABCMeta
from abc import abstractmethod, abstractproperty

import qrcode

from .loggermixin import LoggerMixin
from .modules import login

class MrzyAccount(LoggerMixin):
    def __new__(cls, *, auto_login=False):
        self = super().__new__(cls)
        self.logged_on = False
        self.token = None
        self.open_id = None

        if auto_login:
            self.login()

        return self

    @abstractmethod
    def login(self):
        raise NotImplementedError


class MrzyPwdAccount(MrzyAccount):
    _account_dict = {} # cache for username -> login obj

    def __new__(cls, username, password, *, auto_login=False):
        if (obj := cls._account_dict.get(username)) is not None:
            cls.debug("Found account entry for user %s", username)
            if not obj.logged_on and auto_login:
                obj.login()

            return obj

        cls.debug("Didn't find account entry for user %s", username)
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
        if self.logged_on:
            self.warning("Trying to log in twice!")
            return

        self.info("Logging in...")
        response_json = login.Login(
            login=self.username,
            password=self.password
        ).exec()
        self.token = response_json["data"]["token"]
        self.open_id = response_json["data"]["openId"]
        self.logged_on = True
        self.info("Logged in.")

        self.debug("User Token: %s", self.token)
        self.debug("User Open ID: %s", self.open_id)
