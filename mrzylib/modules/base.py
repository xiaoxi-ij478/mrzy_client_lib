from abc import ABCMeta, abstractmethod
import base64
import hashlib
import json
import os.path

from ..error import RequestError
from ..loggermixin import LoggerMixin
from ..requester import openurl


class JsonAPIBase(LoggerMixin):
    def _get_json(
        self, url, *, headers=None, data=None,
        method=None, what="sending request"
    ):
        with openurl(
            url, data=data, headers=headers, method=method, what=what
        ) as uf:
            response_json = json.load(uf)

        _empty = object()
        if response_json.get("code", _empty) not in (_empty, 200):
            raise RequestError(
                f"Error while {what};\nResponse JSON: {response_json}\n"
            )

        self.debug("Response JSON: %s", response_json)

        return response_json


class ExecAbleAPIBase(LoggerMixin, metaclass=ABCMeta):
    def __init__(self):
        super().__init__()

        self.pre_callbacks = []
        self.progress_callbacks = []
        self.post_callbacks = []

    def add_pre_callback(self, func):
        self.pre_callbacks.append(func)
        return func

    def add_progress_callback(self, func):
        self.progress_callbacks.append(func)
        return func

    def add_post_callback(self, func):
        self.post_callbacks.append(func)
        return func

    def _call_pre_callbacks(self):
        for func in self.pre_callbacks:
            func(self)

    def _call_progress_callbacks(self, *args, **kwargs):
        for func in self.progress_callbacks:
            func(self, *args, **kwargs)

    def _call_post_callbacks(self):
        for func in self.post_callbacks:
            func(self)

    def exec(self):
        self._call_pre_callbacks()
        self._exec_real()
        self._call_post_callbacks()

    @abstractmethod
    def _exec_real(self):
        raise NotImplementedError

class MrzyAPIBase(JsonAPIBase, ExecAbleAPIBase):
    BASE_URL = None
    OPERATING_PATH = None
    REQUEST_METHOD = None
    REQUEST_REASON = "sending request"

    def __init__(self, **args):
        if self.BASE_URL is None or self.OPERATING_PATH is None:
            raise TypeError(f"Cannot create '{self.__class__.__name__}' object")

        self.args = args

    def get_custom_headers(self):
        return {}

    def send_request(self, data):
        return self._get_json(
            os.path.join(self.BASE_URL,  self.OPERATING_PATH),

            headers=self.get_custom_headers(),
            data=data,
            method=self.REQUEST_METHOD,
            what=self.REQUEST_REASON
        )


class MrzyJsonAPIBase(MrzyAPIBase):
    def _exec_real(self):
        return self.send_request(json.dumps(self.args).encode())


class MrzyWithTokenAPIBase(MrzyAPIBase):
    def __init__(self, account_obj, **args):
        super().__init__(**args)

        self.account_obj = account_obj

    def get_custom_headers(self):
        return super().get_custom_headers() | {"token": self.account_obj.token}


class MrzyJsonWithTokenAPIBase(MrzyJsonAPIBase, MrzyWithTokenAPIBase):
    pass


class MrzyLuluAPIBase(MrzyWithTokenAPIBase):
    BASE_URL = "https://lulu.lulufind.com/mrzy/mrzypc/"

    def get_custom_headers(self):
        self.debug("Getting signature for %s", self.args)
        signature = hashlib.md5(
            base64.b64encode(
                json.dumps(self.args, separators=(',', ':')).encode()
            ) +
            b"IF75D4U19LKLDAZSMPN5ATQLGBFEJL4VIL2STVDBNJJTO6LNOGB265CR40I4AL13"
        ).hexdigest()
        self.debug("Signature: %s", signature)
        return super().get_custom_headers() | {"sign": signature}

    def _exec_real(self):
        return self.send_request("&".join(f"{k}={v}" for k, v in self.args.items()).encode())


class MrzyApiProdAPIBase(MrzyJsonWithTokenAPIBase):
    BASE_URL = "https://api-prod.lulufind.com/"
