from abc import ABCMeta
from abc import abstractmethod, abstractproperty

import datetime
import qrcode
import threading
import time

from .base import ExecAbleAPIBase, MrzyApiProdWithoutTokenAPIBase


class _GenQrCodeAPI(MrzyApiProdWithoutTokenAPIBase):
    OPERATING_PATH = "api/v1/auth/genQrCode"
    REQUEST_REASON = "generating QR Code"


class _CheckQrCodeAPI(MrzyApiProdWithoutTokenAPIBase):
    OPERATING_PATH = "api/v1/auth/checkQrCode"
    REQUEST_REASON = "checking QR Code status"


class _LoginAPI(MrzyApiProdWithoutTokenAPIBase):
    OPERATING_PATH = "api/v1/auth/pwdlogin"
    REQUEST_REASON = "logging in"

    def get_custom_headers(self):
        return super().get_custom_headers() | {"Content-Type": "application/json"}


class MrzyAccount(ExecAbleAPIBase, metaclass=ABCMeta):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # the following three variables shall be set after logged on
        self.logged_on = False
        self.token = None
        self.open_id = None

        if self.args.pop("auto_login", False):
            self.exec()


class MrzyQrCodeAccount(MrzyAccount):
    def _gen_qrcode(self):
        link_json = _GenQrCodeAPI().exec()["data"]

        uuid = link_json["code"]
        self.debug(
            "qrcode expire at %s",
            datetime.datetime.fromtimestamp(link_json["expireAt"]).ctime()
        )

        qr_code = qrcode.make(f"https://zuoye.lulufind.com/mp/qrcode/{uuid}")
        return qr_code

    def exec(self):
        if self.logged_on:
            self.warning("Trying to log in twice!")
            return

        # the user will choose which account to login on the
        # mini program, so we won't care about that

        self.info("Logging in...")
        self.debug("Getting QR Code...")
        qr_code = self._gen_qrcode()
        self._call_pre_callbacks(qr_code)

        self.debug("Start waiting for reply...")

        while True:
            resp_json = _CheckQrCodeAPI(code=uuid).exec()

            if resp_json["expired"]:
                self.info("The QR Code has expired.")
                self._call_post_callbacks(expired=True)
                return

            if resp_json["token"]:
                self.info("Logged on.")
                self.logged_on = True
                self.token = resp_json["token"]
                self.open_id = resp_json["user"]["openId"]
                self.debug("User Token: %s", self.token)
                self.debug("User Open ID: %s", self.open_id)

                # we assume the user has logged on now
                self._call_post_callbacks(
                    token=resp_json["token"],
                    open_id=resp_json["user"]["openId"]
                )
                return

            self.debug("No reply, try again")
            time.sleep(2)

        return resp_json

class MrzyPwdAccount(MrzyAccount):
    _account_dict = {} # cache for username -> account token & openid

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.username = self.args.pop("username")
        self.password = self.args.pop("password")

    def exec(self):
        if self.logged_on:
            self.warning("Trying to log in twice!")
            return

        self.info("Logging in...")

        if (obj := self._account_dict.get(username)) is not None:
            self.debug("Found account entry for user %s", username)

            token = obj["token"]
            open_id = obj["open_id"]

        else:
            self.debug("Didn't find account entry for user %s", username)

            response_json = _LoginAPI(
                login=self.username,
                password=self.password
            ).exec()["data"]

            token = response_json["token"]
            open_id = response_json["openId"]
            self._account_dict[self.username] = {
                "token": self.token,
                "open_id": self.open_id
            }

        self.logged_on = True
        self.token = token
        self.open_id = open_id
        self.info("Logged on.")

        self._call_post_callbacks(token=token, open_id=open_id)
            
        self.debug("User Token: %s", token)
        self.debug("User Open ID: %s", open_id)

        return resp_json
