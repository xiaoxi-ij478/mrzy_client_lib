import json
import logging
import urllib.error
import urllib.request

from .error import RequestError

_logger = logging.getLogger(__name__)

# all requests shall be made using this function
# so we can monitor traffic

def openurl(
    url, *, data=None, headers=None, method=None,
    what="sending request"
):
    headers = headers or {}

    _logger.debug("Requesting '%s'", url)

    _logger.debug("Headers:")
    for k, v in headers.items():
        logger.debug("    '%s' = '%s'", k, v)

    _logger.debug("Request method: '%s'", method)

    if data is not None:
        _logger.debug("Request payload: '%s'", data)

    try:
        return urllib.request.urlopen(
            urllib.request.Request(
                url, headers=headers, data=data, method=method
            )
        )
    except urllib.error.HTTPError as e:
        raise RequestError(
            f"Error while {what};\nContent: {e.fp.read()!r}\n"
        ) from e
