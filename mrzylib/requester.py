import logging
import urllib.error
import urllib.request

from .error import RequestError

logger = logging.getLogger(__name__)

# all requests shall be made using this function
# so we can monitor traffic

def openurl(
    url, *, data=None, headers=None, method=None,
    what="sending request"
):
    headers = headers or {}

    logger.debug("Requesting '%s'", url)

    logger.debug("Headers:")
    for k, v in headers.items():
        logger.debug("    '%s' = '%s'", k, v)

    logger.debug("Request method: '%s'", method)

    if data is not None:
        logger.debug("Request payload: '%s'", data)

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
