import logging

class LoggerMixin:
    "Simple mixin logger class using `logging` module."
    # _LOGGER = logging.getLogger() # the base class uses root logger

    def __init_subclass__(cls):
        cls._LOGGER = logging.getLogger(cls.__qualname__)

    def debug(self, *args, **kwargs):
        self._LOGGER.debug(*args, **kwargs)

    def info(self, *args, **kwargs):
        self._LOGGER.info(*args, **kwargs)

    def warning(self, *args, **kwargs):
        self._LOGGER.warning(*args, **kwargs)

    def error(self, *args, **kwargs):
        self._LOGGER.error(*args, **kwargs)

    def critical(self, *args, **kwargs):
        self._LOGGER.critical(*args, **kwargs)

    def exception(self, *args, **kwargs):
        self._LOGGER.exception(*args, **kwargs)
