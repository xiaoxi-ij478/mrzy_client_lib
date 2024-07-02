#!/usr/bin/env python3

import base64
import datetime
import enum
import hashlib
import io
import json
import logging
import mimetypes
import os.path
import random
import sys
import time
import urllib.error
import urllib.request

# note: we can bypass the cache by adding arbitrary query params
# to the url, like "https://img2.lulufind.com/ff?......."

class BaseError(Exception):
    "The base class for all the errors"

class RequestError(BaseError):
    "Error while requesting the server."

class UploadError(BaseError):
    "Error while uploading."

class CommandLineError(BaseError):
    "Error while parsing command line."

class LoggerBase:
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


class JSONAPIBase:
    """JSON API mixin class.
    Requires `LoggerBase` for logging."""

    def _internal_send_request(
        self, url, header=None, data=None, method=None, what="sending request",
        verify_json=True, throw_exc=True
    ):
        # see the class docstring for details
        # pylint: disable=no-member
        """For internal usage only.
        Send request directly to url.

        Arguments:
                url:  Request URL
             header:  Custom header
               data:  POST data (if None then GET will be used)
             method:  Force request method (overrides `data`)
               what:  A string describing your request
        verify_json:  Verify the JSON's returned "code" is 200
          throw_exc:  Raise exception when error occurred
                             (if False then print an error message and continue)
        """
        header = header or {}

        self.debug("Requesting %s", url)
        self.debug("Headers:")
        for k, v in header.items():
            self.debug("    %s: %s", k, v)
        if data is not None:
            self.debug("POST data: %s", data)

        if isinstance(data, dict):
            data = json.dumps(data).encode()

        try:
            response_json = json.load(
                urllib.request.urlopen(
                    urllib.request.Request(url, headers=header, data=data, method=method)
                )
            )
        except Exception as e:
            if throw_exc:
                raise RequestError("Error while %s." % what) from e
            self.exception("Error while %s.", what)

        if verify_json:
            _empty = object()
            if response_json.get("code", _empty) is _empty:
                self.warning('verify_json is True but "code" could not be found')
                self.warning('assuming success')
            else:
                if response_json.get("code", 200) != 200:
                    if throw_exc:
                        raise RequestError("Error while %s. Response JSON: %s." % (what, response_json))
                    self.error("Error while %s. Response JSON: %s.", what, response_json)

        self.debug("Response JSON: %s", response_json)

        return response_json


class MrzyAccount(LoggerBase, JSONAPIBase):
    "Represent an Meirizuoye account."

    _account_dict = {} # username -> login json

    def __init__(self, username, password):
        """Create an account instance.
        Arguments:

        username, password:  The username and password used for login, respectively
        """

        self.username = username
        self.password = password
        self.account_token = None # account token, set by login()

    def _internal_send_request(
        self, url, header=None, data=None, method=None, what="sending request",
        verify_json=True, throw_exc=True, sign=True
    ):
        """For internal usage only.
        Send request directly to url, optionally check
        for the JSON signature.

        Arguments:
                url:  Request URL
             header:  Custom header
               data:  POST data (if None then GET will be used)
               sign:  Encode data to wwwform, and check for signature (for JSON only)
               what:  A string describing your request
        verify_json:  Verify the JSON's returned "code" is 200
          throw_exc:  Raise exception when error occurred
                         (if False then print an error message and continue)
        """

        header = header or {}

        if sign:
            if isinstance(data, dict):
                if self.account_token is None:
                    self.warning("The user has not logged in while %s." % what)
                    self.warning("Now trying to log in.")
                    self.login()

                header["token"] = self.account_token
                header["sign"] = self.get_json_sign(data)
                data = "&".join(map("=".join, data.items())).encode()

            else:
                self.warning("sign is True but data is not a dictionary")
                self.warning("data: %s", data)

        response_json = super()._internal_send_request(
            url, header, data, method, what, verify_json, throw_exc
        )

        return response_json

    def get_json_sign(self, json_data):
        """Get the signature for a JSON.
        Arguments:

        json_data: The JSON preparing to sign.
        """

        self.debug("Getting signature for %s", json_data)
        signature = hashlib.md5(
            base64.b64encode(
                json.dumps(json_data, separators=(',', ':')).encode()
            ) +
            b"IF75D4U19LKLDAZSMPN5ATQLGBFEJL4VIL2STVDBNJJTO6LNOGB265CR40I4AL13"
        ).hexdigest()
        self.debug("Signature: %s", signature)

        return signature

    def login(self):
        """Login to the account.
        This method sets `self.account_token`.
        """

        if self.account_token is not None:
            self.warning("Trying to logging twice!")

        self.info("Logging in...")

        if self._account_dict.get(self.username):
            self.debug("Token cache entry found for user %s", self.username)
            self.account_token = self._account_dict[self.username]["data"]["token"]
        else:
            self.debug("Token cache entry not found for user %s", self.username)
            response_json = self._internal_send_request(
                "https://api-prod.lulufind.com/api/v1/auth/pwdlogin",
                header={"Content-Type": "application/json"},
                data={"login": self.username, "password": self.password},
                sign=False, what="logging in"
            )
            self._account_dict[self.username] = response_json
            self.account_token = response_json["data"]["token"]

        self.info("Logged in.")

        self.debug("User token: %s", self.account_token)

    def send_mrzy_request(self, url, data, what="requesting Meirizuoye's API"):
        """Send request to Meirizuoye's API.
        This request method automatically calculates signature
        for the request JSON.
        Arguments:

             url: Request's URL
            data: POST dictionary
            what: A string describing your request
        """

        return self._internal_send_request(url, data=data, what=what)


class QiniuUploader(LoggerBase, JSONAPIBase):
    """The qiniu file uploader class.
    The regular SDK could not be used because we don't have
    accesskey / secretkey (and I don't want to use it either)
    """

    # emulate a file-like interface

    class _Status(enum.IntEnum):
        UNINITIALIZED = 0
        UPLOADING = 1
        DONE = 2


    def __init__(self, src_file, rmt_filename, mime_type, upload_token):
        """Create a qiniu file uploader instance.

        Arguments:
                src_file:  Source file object, must opened for binary reading
            rmt_filename:  Remote filename
               mime_type:  The remote file MIME type
            upload_token:  Uptoken used for upload
        """

        self.src_file = src_file
        self.rmt_filename = rmt_filename
        self.base64_enc_rmt_filename = base64.b64encode(rmt_filename.encode()).decode()
        self.mime_type = mime_type
        self.upload_token = upload_token # set later
        self.blocks = []
        self.block_num = 1
        self.upload_id = ""
        self.upload_status = self._Status.UNINITIALIZED


    def __del__(self):
        try:
            if self.upload_status == self._Status.UPLOADING:
                self.abort_upload()
        except:
            pass

    def _check(self):
        """Sanity check before doing any operation:
        - If this uploader has been done
        - If there's no upload token
        """
        if self.upload_status == self._Status.DONE:
            raise UploadError("Trying to operate on a done uploader object.")

        if not self.upload_token:
            raise UploadError("Upload token has not been set.")

    @staticmethod
    def size_to_human_readable(size):
        """Convert a size to human readable size.

        Arguments:
            size: Size
        """

        suffixes = ['B', "KiB", "MiB", "GiB", "TiB", "EiB", "ZiB", "YiB"]
        suffix = 0 # suffixes index

        while size >= 1024 and suffix <= 7:
            size /= 1024
            suffix += 1

        return "%.2f%s" % (size, suffixes[suffix])

    def begin_upload(self):
        """Begin the upload.
        This method gets the upload ID for uploading.
        This method sets `self.upload_id`.
        """

        self._check()

        if self.upload_status != self._Status.UNINITIALIZED:
            raise UploadError("Trying to begin upload after initialized.")

        self.info("Initializing upload...")
        response_json = self._internal_send_request(
            "https://upload-z2.qiniup.com/"
            "buckets/mrzy/objects/%s/uploads" % self.base64_enc_rmt_filename,
            header={"Authorization": "UpToken " + self.upload_token},
            method="POST", what="initializing upload"
        )

        self.upload_id = response_json["uploadId"]
        self.upload_status = self._Status.UPLOADING

        self.info("Got upload ID.")
        self.debug("Upload ID is %s", self.upload_id)
        self.debug(
            "Update expires at %s",
            datetime.datetime.fromtimestamp(response_json["expireAt"]).ctime()
        )

    def abort_upload(self):
        """Abort the upload.
        This method order the server to stop the current upload session.
        This method sets `self.upload_id` to "" and `self.block_num` to 1.
        """

        self._check()

        if self.upload_status != self._Status.UPLOADING:
            raise UploadError("Trying to abort upload before initialized.")

        self.info("Aborting upload...")
        self._internal_send_request(
            "https://upload-z2.qiniup.com/"
            "buckets/mrzy/objects/%s/uploads/%s" % (
                self.base64_enc_rmt_filename,
                self.upload_id
            ),
            header={"Authorization": "UpToken " + self.upload_token},
            method="DELETE", what="aborting upload"
        )
        self.info("Aborted.")

        self.upload_id = ""
        self.block_num = 1
        self.upload_status = self._Status.UNINITIALIZED

    def write_block(self, data):
        """Upload data to the server.

        Arguments:
            data:  Bytes-like object to upload.
        """

        self._check()

        if self.upload_status != self._Status.UPLOADING:
            raise UploadError("Trying to write before initialized.")

        response_json = self._internal_send_request(
            "https://upload-z2.qiniup.com/"
            "buckets/mrzy/objects/%s/uploads/%s/%s" % (
                self.base64_enc_rmt_filename,
                self.upload_id,
                self.block_num
            ),
            header={
                "Authorization": "UpToken " + self.upload_token,
                "Content-Type": "application/octet-stream",
                "Content-MD5": hashlib.md5(data).hexdigest(),
                "Content-Length": len(data)
            },
            data=data,
            method="PUT",
            what="writing block"
        )
        self.blocks.append(
            {
                "etag": response_json["etag"],
                "partNumber": self.block_num
            }
        )
        self.block_num += 1

    def finish_upload(self):
        """Finish the upload.
        This method commits all the blocks to the server.
        This method sets `self.upload_status` to `DONE`,
        and from then on no further operation can be done.
        """

        self._check()

        self.info("Finishing upload...")
        self._internal_send_request(
            "https://upload-z2.qiniup.com/"
            "buckets/mrzy/objects/%s/uploads/%s" % (
                self.base64_enc_rmt_filename,
                self.upload_id
            ),
            header={
                "Content-Type": "application/json",
                "Authorization": "UpToken " + self.upload_token
            },
            data={
                "fname": self.rmt_filename,
                "mimeType": self.mime_type,
                "parts": self.blocks
            },
            what="finishing upload"
        )
        self.info("Upload finished.")
        self.upload_status = self._Status.DONE


class MrzyFileUploader(LoggerBase):
    "The main Meirizuoye file uploader class."

    UPLOAD_SPLIT_CHUNK_SIZE = 3 * 1024 * 1024

    def __init__(
        self, username, password, src_filepath, filesize=None,
        src_filename=None, rmt_filename=None, mime_type=None, get_token_api=2,
        output_link_filepath='-', add_to_filelist=False
    ):
        """Create a file uploader instance.
        Arguments:

          username, password:  Passed to `MrzyAccount`
                src_filepath:  Source file path
                    filesize:  Source file size, overrides `src_file`, default None
                src_filename:  Source file name, overrides `src_file`, default None
                rmt_filename:  Forced remote file name,
                                   if None (default), then calculated automatically
                   mime_type:  Forced remote file MIME type,
                                   if None (default), then calculated from the extension
               get_token_api:  The token getter API version (default 2),
                                   for differences see the help text
        output_link_filepath:  The file path used for writing the result link (default '-')
             add_to_filelist:  Add this file to the logged on account's private file list
                               (default `False`)
        """

        try:
            if src_filepath == '-':
                self.src_file = sys.stdin.buffer
            else:
                self.src_file = open(src_filepath, "rb")
        except IOError as e:
            raise UploadError("source file must be readable") from e

        try:
            if output_link_filepath == '-':
                self.output_link_file = sys.stdout
            else:
                self.output_link_file = open(output_link_filepath, "w")
        except IOError as e:
            raise UploadError("output link file must be writable") from e

        self.filesize = filesize
        self.src_filename = src_filename or self.src_file.name
        self.rmt_filename = rmt_filename or self.get_default_upload_filename()
        self.mime_type = (
            mime_type or
            mimetypes.guess_type(self.src_filename)[0] or
            "application/octet-stream"
        )
        self.get_token_api = get_token_api
        self.add_to_filelist = add_to_filelist
        self.file_link = "https://img2.lulufind.com/" + self.rmt_filename
        self.mrzy_account_obj = MrzyAccount(username, password)
        self.qiniu_uploader_obj = QiniuUploader(
            self.src_file,
            self.rmt_filename,
            self.mime_type,
            ""
        )

    def get_default_upload_filename(self):
        """Get the default upload filename. (For token getter API v2 only)

        Forming pattern:
            (work|file)/(image|audio|video|other)/(student|teacher|other)/<real_filename>

            Where <real_filename> is:
                <unix timestamp> + "_" +
                <user's open ID (but we use 0 for privacy)> + "_" +
                <random number> + "_" +
                (only for video, but we don't use) "_duration=" + <video's duration> +
                <file extension>
        """

        filename = "file/other/student/%d_%s_%d_%s" % (
            int(time.time()),
            "u0000000000000000",
            random.randint(0, 99999999),
            os.path.splitext(self.src_filename)[1]
        )
        self.debug("Generated remote filename: %s", filename)

        return filename

    def get_upload_token(self):
        """Get the upload token for the remote file.
        Sets `self.qiniu_uploader_obj.upload_token`.
        """

        token = self.mrzy_account_obj.send_mrzy_request(
            "https://lulu.lulufind.com/mrzy/mrzypc/getQiniuToken" +
            ("V2" if self.get_token_api == 2 else ""),
            data={"keys": self.rmt_filename},
            what="getting upload token"
        )["data"][self.rmt_filename]

        self.debug("Upload token: %s", token)
        self.qiniu_uploader_obj.upload_token = token

    def _print_progress(self, cur_size, total_size, speed):
        """For Internal usage only.
        Print upload progress to the terminal.

        Arguments:
            cur_size: Current uploaded bytes
            total_size: File's total size (0 if unknown)
            speed: Upload speed (bytes per second)
        """
        # if we're not in terminal, or the logging level is above INFO,
        # then don't print (we're INFO-level log)

        if not sys.stderr.isatty() or logging.getLogger().level > logging.INFO:
            return

        print(
            "%.2f%%     %s/%s     %s/s               " % (
                0 if not total_size else (cur_size / total_size * 100),
                self.qiniu_uploader_obj.size_to_human_readable(cur_size),
                self.qiniu_uploader_obj.size_to_human_readable(total_size),
                self.qiniu_uploader_obj.size_to_human_readable(speed)
            ),
            end='\r',
            file=sys.stderr
        )

    def upload_file(self):
        """Begin uploading the file.
        The most important one. :)"""

        self.info('Preparing to uploading file "%s"...', self.src_filename)
        self.mrzy_account_obj.login()
        self.get_upload_token()

        uploaded = 0

        if self.filesize is None:
            if self.src_file.seekable():
                self.src_file.seek(0, io.SEEK_END)
                self.filesize = self.src_file.tell()
                self.src_file.seek(0, io.SEEK_SET)
            else:
                self.filesize = 0

        begin_time = time.time()
        self.info("Uploading...")
        self.debug("Begin at: %s", begin_time)
        self.info(
            "Size: %d (%s)",
            self.filesize,
            self.qiniu_uploader_obj.size_to_human_readable(self.filesize)
        )

        self.qiniu_uploader_obj.begin_upload()

        while buffer := self.src_file.read(self.UPLOAD_SPLIT_CHUNK_SIZE):
            self.debug("Read %d bytes", len(buffer))
            self.qiniu_uploader_obj.write_block(buffer)
            uploaded += len(buffer)
            self._print_progress(uploaded, self.filesize, uploaded / (time.time() - begin_time))

        self._print_progress(uploaded, self.filesize, uploaded / (time.time() - begin_time))
        if sys.stderr.isatty() and logging.getLogger().level <= logging.INFO:
            print(file=sys.stderr)

        # do not close stdin
        if self.src_file is not sys.stdin.buffer:
            self.src_file.close()

        self.qiniu_uploader_obj.finish_upload()

        if self.add_to_filelist:
            self.info("Commiting to Meirizuoye...")
            self.commit_to_mrzy(self.filesize or uploaded) # in case it's stdin or pipe, etc.
            self.info("Commited.")

        print(self.file_link, file=self.output_link_file)
        if self.output_link_file is not sys.stdout:
            self.output_link_file.close()

        self.info("Uploaded.")

    def commit_to_mrzy(self, file_size):
        """Commit file to Meirizuoye.
        Arguments:

            file_size: File's size (0 if unknown, but should not happen)
        """
        file_info = {
            "name": os.path.basename(self.src_filename),
            "type": os.path.splitext(self.src_filename)[1],
            "size": str(file_size),
            "fileUrl": self.file_link
        }

        self.mrzy_account_obj.send_mrzy_request(
            "https://lulu.lulufind.com/mrzy/mrzypc/addUserFile",
            data=file_info, what="commiting to Meirizuoye"
        )

def print_help(prog_name):
    print(
        """\
Usage: %s <file to upload> [options] ...
Upload files to Meirizuoye.
File may be '-' to read from stdin

Note: before using this tool, make sure you have bound a password account!

  -q, --quiet                         Let the program shut up (set the logging level to CRITICAL)
      This option will override any other logging level settings
  -l, --logging <logging_level>       Adjust the logging level (default INFO)
      (possible values: DEBUG, INFO, WARNING, ERROR, CRITICAL)
  -u, --user  <username>              (pre-file) Username for login
  -p, --pass  <password>              (pre-file) Password for login
      (for security reasons it is suggested to use the --passfile option below)
  -P, --passfile  <password file>     (pre-file) File with username and password
      (format: <username> <password>)
  -s, --size  <file size>             (pre-file) Specify file size (useful for pipes etc.)
  -n, --lfilename  <filename>         (pre-file) Force local filename (useful for pipes etc.)
  -t, --mimetype  <mimetype>          (pre-file) The type of file, in MIME
  -r, --rfilename  <remote filename>  (pre-file) Remote file name
      (be careful when using this option, you may overwrite other files!)
  -g, --get-token-api  <version>      (pre-file) Get Token API to use (1/2, default 2)
  -o, --output-link  <filename>       (pre-file) Print the file link to the file
  -a, --add-to-filelist               (pre-file) Add your uploaded file to your file list
  -h, --help       Display this help

Get Token API description:
With Get Token API v1 you can specify arbitrary remote path,
  and with Get Token API v2 you need to specify the remote path as follows:
    "(work|file)/(image|audio|video|other)/(student|teacher|other)/<RFILENAME>"
BUT PERSONALLY I STRONGLY NOT RECOMMEND TO UPLOAD TO SOMETHING LIKE "/foo"!!!\
""" % prog_name,
        file=sys.stderr
    )

def main(argc, argv):
    if argc == 1:
        print_help(argv[0])
        return 1

    file_entry = []
    iargv = iter(argv[1:])
    no_more_option = False
    logging_level = "INFO"

    while True:
        try:
            option = next(iargv)
            if option == "--":
                # stop parsing right away
                break

            if option in ("-q", "--quiet"):
                logging_level = "!CRITICAL"

            elif option in ("-l", "--logging"):
                if logging_level[0] != "!":
                    if (argument := next(iargv).upper()) not in (
                        "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
                    ):
                        raise CommandLineError(
                            "Invalid loggging level. Valid: DEBUG, INFO, WARNING, ERROR, CRITICAL."
                        )

                    logging_level = argument

            elif option in ("-u", "--user"):
                file_entry[-1]["username"] = next(iargv)

            elif option in ("-p", "--pass"):
                file_entry[-1]["password"] = next(iargv)

            elif option in ("-P", "--passfile"):
                with open(next(iargv), encoding="UTF-8") as f:
                    file_entry[-1]["username"], file_entry[-1]["password"] = \
                        f.readline().strip().split(maxsplit=1)

            elif option in ("-s", "--size"):
                file_entry[-1]["filesize"] = int(next(iargv))

            elif option in ("-n", "--lfilename"):
                file_entry[-1]["src_filename"] = next(iargv)

            elif option in ("-t", "--type"):
                file_entry[-1]["mime_type"] = next(iargv)

            elif option in ("-r", "--rfilename"):
                file_entry[-1]["rmt_filename"] = next(iargv)

            elif option in ("-g", "--get-token-api"):
                if (argument := next(iargv)) not in ('1', '2'):
                    raise ValueError("Invalid API version. Valid: 1, 2.")

                file_entry[-1]["get_token_api"] = int(argument)
                del argument

            elif option in ("-o", "--output-link"):
                file_entry[-1]["output_link_file"] = next(iargv)

            elif option in ("-a", "--add-to-filelist"):
                file_entry[-1]["add_to_filelist"] = True

            elif option in ("-h", "--help"):
                print_help(argv[0])
                return 0

            elif len(option) > 1 and option[0] == '-':
                raise CommandLineError("option %s not recognized" % option)

            else:
                file_entry.append({"src_file": option})

        except StopIteration:
            no_more_option = True
            break

    if not no_more_option:
        while True:
            try:
                filename = next(iargv)
                file_entry.append({"src_file": filename})
            except StopIteration:
                break

    if not file_entry:
        print_help(argv[0])
        return 1

    logging.basicConfig(level=getattr(logging, logging_level.strip('!')))
    _empty = object()

    for file in file_entry:
        logging.debug("Initializing MrzyFileUploader with the following arguments:")
        for k, v in file.items():
            logging.debug('%s="%s"', k, v)

        if file.get("username", _empty) is _empty or file.get("password", _empty) is _empty:
            logging.error('"%s" has no username or password.', file.get("src_filename", file["src_file"].name))
            logging.error("This file will be ignored.")
            continue

        MrzyFileUploader(**file).upload_file()

    return 0

if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
