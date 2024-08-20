from .base import MrzyJsonAPIBase as _MrzyJsonAPIBase


class Login(_MrzyJsonAPIBase):
    BASE_URL = "https://api-prod.lulufind.com/"
    OPERATING_PATH = "api/v1/auth/pwdlogin"
    REQUEST_REASON = "logging in"

    def get_custom_headers(self):
        return super().get_custom_headers() | {"Content-Type": "application/json"}
