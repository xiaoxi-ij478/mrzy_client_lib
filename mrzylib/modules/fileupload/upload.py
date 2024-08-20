import io
import mimetypes
import os.path
import random
import time

from . import tokengetter, uploader
from ..base import ExecAbleAPIBase


# this class does nothing more than uploading the file;
# to use it as a console application (with progress bar, etc.),
# use the standalone script
class UploadBase(ExecAbleAPIBase):
    UPLOAD_SPLIT_CHUNK_SIZE = 3 * 1024 * 1024 # 3 MiB
    UPLOAD_FILE_URL_BASE = "https://img2.lulufind.com/"
    TOKEN_GETTER = None

    def __init__(self, account_obj, **args):
        if self.TOKEN_GETTER is None:
            raise TypeError("Cannot create 'UploadBase' instance")

        self.account_obj = account_obj
        self.src_filename = args.pop("src_filename")
        self.rmt_filename = args.pop(
            "rmt_filename", self.get_default_upload_filename()
        )
        self.mime_type = args.pop(
            "mime_type",
            mimetypes.guess_type(self.src_filename)[0] or
            "application/octet-stream"
        )
        self.upload_token = args.pop("upload_token", None)
        self.pre_upload_callback_list = args.pop("pre_upload_callback_list", [])
        self.upload_progress_callback_list = args.pop("upload_progress_callback_list", [])
        self.post_upload_callback_list = args.pop("post_upload_callback_list", [])


    def get_default_upload_filename(self):
        """Get the default upload filename.

        Forming pattern:
            (album|work|file)/(image|audio|video|other)/(student|teacher|other)/<real_filename>

            Where <real_filename> is:
                <unix timestamp (in nanoseconds (we use) / microseconds)> + "_" +
                <user's open ID (but we use 0 for privacy)> + "_" +
                <random number> + "_" +
                (only for video, but we don't use) "_duration=" + <video's duration> +
                <file extension>
        """

        filename = "file/other/student/{:d}_{}_{:d}_{}".format(
            time.time_ns(),
            "u0000000000000000",
            random.randint(0, 99999999),
            os.path.splitext(self.src_filename)[1]
        )
        self.debug("Generated remote filename: %s", filename)

        return filename

    def exec(self):
        uploaded = 0

        self.info('Preparing to uploading file "%s"...', self.src_filename)

        self.info("Getting upload token...")
        token = (
            self.upload_token or
            # we will assign a callable to TOKEN_GETTER in subclasses
            # pylint: disable=not-callable
            self.TOKEN_GETTER(self.account_obj).exec(
                keys=[self.rmt_filename]
            )["data"][self.rmt_filename]
        )
        self.info("Got upload token.")
        self.debug("Upload token: %s", token)

        uploader_obj = uploader.QiniuUploader(self.rmt_filename, self.mime_type, token)
        uploader_obj.begin_upload()

        begin_time = time.time()

        with open(self.src_filename, "rb") as file_obj:
            file_obj.seek(0, io.SEEK_END)
            file_size = file_obj.tell()
            file_obj.seek(0, io.SEEK_SET)
            for i in self.pre_upload_callback_list:
                i(self.src_filename, self.rmt_filename, file_size, begin_time)

            while buffer := file_obj.read(self.UPLOAD_SPLIT_CHUNK_SIZE):
                uploader_obj.write_block(buffer)
                uploaded += len(buffer)
                for i in self.upload_progress_callback_list:
                    i(self.src_filename, self.rmt_filename, file_size, begin_time, time.time())

        uploader_obj.finish_upload()
        for i in self.post_upload_callback_list:
            i(self.src_filename, self.rmt_filename, file_size, begin_time, time.time())

        self.info("Upload finished.")

        return os.path.join(self.UPLOAD_FILE_URL_BASE, self.rmt_filename)

class UploadV1(UploadBase):
    TOKEN_GETTER = tokengetter.TokenGetter

class UploadV2(UploadBase):
    TOKEN_GETTER = tokengetter.TokenGetterV2
