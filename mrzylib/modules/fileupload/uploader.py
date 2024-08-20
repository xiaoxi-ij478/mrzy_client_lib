import atexit
import base64
import datetime
import hashlib

from ..base import JsonAPIBase
from ...error import UploadError

class QiniuUploader(JsonAPIBase):
    # see https://developer.qiniu.com/kodo/6364/multipartupload-interface
    BEGIN_UPLOAD_URL  = "https://upload-z2.qiniup.com/buckets/mrzy/objects/%s/uploads"
    ABORT_UPLOAD_URL  = "https://upload-z2.qiniup.com/buckets/mrzy/objects/%s/uploads/%s"
    WRITE_BLOCK_URL   = "https://upload-z2.qiniup.com/buckets/mrzy/objects/%s/uploads/%s/%d"
    FINISH_UPLOAD_URL = "https://upload-z2.qiniup.com/buckets/mrzy/objects/%s/uploads/%s"

    class _Status:
        UNINITIALIZED = 0
        UPLOADING = 1
        DONE = 2


    def __init__(self, rmt_filename, mime_type, upload_token):
        self.rmt_filename = rmt_filename
        self.base64_enc_rmt_filename = base64.b64encode(rmt_filename.encode()).decode()
        self.mime_type = mime_type
        self.upload_token = upload_token
        self.blocks = []
        self.block_num = 1
        self.upload_id = ""
        self.upload_status = self._Status.UNINITIALIZED
        atexit.register(self._force_close)

    def __del__(self):
        self._force_close()
        atexit.unregister(self._force_close)

    def _force_close(self):
        try:
            if self.upload_status == self._Status.UPLOADING:
                self.abort_upload()
        except:
            pass

    def _check(self):
        if self.upload_status == self._Status.DONE:
            raise UploadError("Trying to operate on a done uploader object.")

        if not self.upload_token:
            raise UploadError("Upload token has not been set.")

    def begin_upload(self):
        self._check()

        if self.upload_status != self._Status.UNINITIALIZED:
            raise UploadError("Trying to begin upload after initialized.")

        self.info("Initializing upload...")
        response_json = self._send_request(
            self.BEGIN_UPLOAD_URL % self.base64_enc_rmt_filename,

            headers={"Authorization": f"UpToken {self.upload_token}"},
            method="POST",
            what="initializing upload"
        )

        self.upload_id = response_json["uploadId"]
        self.upload_status = self._Status.UPLOADING

        self.info("Upload initialized.")
        self.info("Got upload ID.")
        self.debug("Upload ID is %s", self.upload_id)
        self.debug(
            "Update expires at %s",
            datetime.datetime.fromtimestamp(response_json["expireAt"]).ctime()
        )

    def abort_upload(self):
        self._check()

        if self.upload_status != self._Status.UPLOADING:
            raise UploadError("Trying to abort upload before initialized.")

        self.info("Aborting upload...")
        self._send_request(
            self.ABORT_UPLOAD_URL % (self.base64_enc_rmt_filename, self.upload_id),

            headers={"Authorization": f"UpToken {self.upload_token}"},
            method="DELETE",
            what="aborting upload"
        )
        self.info("Aborted.")

        self.upload_id = ""
        self.block_num = 1
        self.upload_status = self._Status.UNINITIALIZED

    def write_block(self, data):
        self._check()

        if self.upload_status != self._Status.UPLOADING:
            raise UploadError("Trying to write before initialized.")

        response_json = self._send_request(
            self.WRITE_BLOCK_URL % (self.base64_enc_rmt_filename, self.upload_id, self.block_num),

            headers={
                "Authorization": f"UpToken {self.upload_token}",
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
        self._check()

        self.info("Finishing upload...")
        self._send_request(
            self.FINISH_UPLOAD_URL % (self.base64_enc_rmt_filename, self.upload_id),

            headers={
                "Content-Type": "application/json",
                "Authorization": f"UpToken {self.upload_token}"
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
