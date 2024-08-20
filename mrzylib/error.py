class BaseError(Exception):
    "The base class for all the errors"


class RequestError(BaseError):
    "Error while requesting the server."


class UploadError(BaseError):
    "Error while uploading."


class NoUploadToRootDirectoryError(UploadError):
    "Error when trying to upload to root directory."


class NoUploadToExistingFileError(UploadError):
    "Error when trying to upload to existing files."


class CommandLineError(BaseError):
    "Error while parsing command line."
