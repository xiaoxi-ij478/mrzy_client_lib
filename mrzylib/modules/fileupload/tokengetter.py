from ..base import MrzyLuluAPIBase

class TokenGetter(MrzyLuluAPIBase):
    OPERATING_PATH = "getQiniuToken"
    REQUEST_REASON = "getting upload token"

class TokenGetterV2(MrzyLuluAPIBase):
    OPERATING_PATH = "getQiniuTokenV2"
    REQUEST_REASON = "getting upload token"
