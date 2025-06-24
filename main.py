#!/usr/bin/env python

import argparse
import os
import random
import shlex
import subprocess
import sys
import time


class TcUpload:

    DEF_PARALLEL = 3

    def __init__(self, url, max_parallel, auth):
        self.uploaders = []
        self.max_parallel = max_parallel
        self.auth = auth

        self.cmd_base = ['curl',
                         '-X', 'POST',
                         '--location',
                         '--insecure',
                         '--header', 'Content-Type: application/json',
                         '--header', 'Accept: application/json',
                         url,
                        ]

        self.time_start = None
        self.cnt_expected = 0
        self.cnt_total = 0
        self.cnt_failed = 0

    def upload_dir(self, path, scan_first):
        print('Going to upload {} with {} threads'.format(
            path, self.max_parallel))

        for file_path in self.find_files(path):
            self.cnt_expected += 1

        # FIXME: safety counter, abort after this many uploads (0 == disabled)
        debug_cnt = 0
        class DebugExc(Exception):
            def __init__(self):
                super().__init__('Debug exit')

        try:
            for file_path in self.find_files(path):
                self.curl_or_wait(file_path)
                debug_cnt -= 1
                if debug_cnt == 0:
                    raise DebugExc()
        except DebugExc as e:
            self.finalize()
            print(e)
        except KeyboardInterrupt:
            self.finalize()
        # unexpected error:
        except Exception as e:
            # - try to print what we catched
            print(e)
            # - try still to finalize
            self.finalize()
            # - and re-raise the error again
            raise

        sys.exit(int(self.cnt_failed > 0))

    def find_files(self, path):
        folders = [path]
        for d in folders:
            for dentry in os.scandir(d):
                if dentry.is_dir():
                    folders.append(dentry)
                elif dentry.is_file():
                    yield dentry.path

    def finalize(self):
        self.wait_for_parallel(for_all=True)
        print('== Uploaded {total} files, with {failed} failures =='.format(
            total=self.cnt_total,
            failed=self.cnt_failed))

    def curl_or_wait(self, jsonfile):
        cmd = self.cmd_base[:]

        if self.auth:
            # token is added to cmd here, as ideally it should be obtained/refreshed
            # just here before upload
            cmd.append('--header')
            cmd.append('Authorization: Bearer {t}'.format(t=self.auth))

        cmd.append('--upload-file')
        cmd.append(jsonfile)

        # FIXME: just for testing
        #cmd = ['ping', '-c3', 'localhost']

        self.wait_for_parallel()

        self.uploaders.append(
            subprocess.Popen(
                cmd,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE))

        self.print_progress()

    def print_progress(self):
        if self.cnt_expected != 0:
            print(
                '\rUploading file {} from {} [ETA: {}]     '.format(
                    self.cnt_total,
                    self.cnt_expected,
                    self.estimate_time()),
                end='',
                flush=True)
        else:
            print(
                '\rUploading file {}'.format(
                    self.cnt_total),
                end='',
                flush=True)

    def estimate_time(self):
        if self.time_start is None:
            self.time_start = time.perf_counter()
            return '??'
        else:
            elapsed_sec = time.perf_counter() - self.time_start
            file_per_sec = self.cnt_total / elapsed_sec

            remaining_files = self.cnt_expected - self.cnt_total
            eta_sec = remaining_files / file_per_sec

            # format hours extra as those are optional
            # only minutes and seconds are shown always
            h_s = ''
            if eta_sec > 3600:
                h_s = '{:02d}h '.format(int(eta_sec / 3600))
                eta_sec = eta_sec % 3600

            m = int(eta_sec / 60)
            s = int(eta_sec % 60)
            return '{}{:02d}m {:02d}s'.format(h_s, m, s)

    def wait_for_parallel(self, for_all=False):
        # wait for all or some uploads to finish
        needed_max_count = 0 if for_all else (self.max_parallel - 1)
        while len(self.uploaders) > needed_max_count:
            time.sleep(0.05)
            # process any finished or failed uploads
            for uploader in self.uploaders:
                if uploader.poll() is not None:
                    # uploader with return code is already finished
                    self.cnt_total += 1
                    if uploader.returncode != 0:
                        self.cnt_failed += 1
                        # curl failed print errors:
                        print('') # terminate inline status update
                        print(shlex.join(uploader.args))
                        print(uploader.stderr.read())
                    self.uploaders.remove(uploader)


def parse_args(args):
    p = argparse.ArgumentParser()
    p.add_argument('source_dir',
                   help='Source directory with (sbom/csaf) json files')
    p.add_argument('target_url',
                   help='Upload URL of Trustify API'
                   ' (with /api/v2/sbom or csaf)')
    p.add_argument('token',
                   nargs='?',
                   default='',
                   help='HTTP bearer token for Trustify API (optional)')
    p.add_argument('-p', '--max-parallel',
                   type=int,
                   default=TcUpload.DEF_PARALLEL,
                   help=('Limit of parallel uploads'
                         ' performed at the same time'
                         ' (default: {})'.format(TcUpload.DEF_PARALLEL)))
    p.add_argument('-s', '--scan-first',
                   action='store_true',
                   default=False,
                   help='Count files before uploading'
                   ' (slower but provides status and estimation)')
    return p.parse_args(args)


if __name__ == '__main__':

    print("***Welcome to Trustification file uploader tool!***")
    if len(sys.argv) >= 2:
        args = parse_args(sys.argv[1:])

        print(args)

        path = args.source_dir
        url = args.target_url
        token = args.token
        max_p = args.max_parallel
        scan_first = args.scan_first
    else:
        path = input("Please enter the path to upload your SBOM or CSAF files from: ")  # Enter the files' path
        url = input("Please enter the server URL to upload the files to: ")   # Enter the remote server URL to upload files
        token = input("Please enter the bearer token: ")  # Enter the bearer token of Trustification api server
        max_p = input("Please enter max parallel count [{}]: "
                      .format(TcUpload.DEF_PARALLEL))
        max_p = int(max_p if len(max_p) else TcUpload.DEF_PARALLEL)
        scan_first = False

    TcUpload(url, max_p, token).upload_dir(path, scan_first)

