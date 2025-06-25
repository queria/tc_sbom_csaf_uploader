#!/usr/bin/env python

import argparse
import base64
import json
import os
import random
import shlex
import subprocess
import sys
import time


class TcUpload:

    DEF_PARALLEL = 3
    DEF_TOKEN_RESERVE_SEC = 3

    def __init__(self, url, max_parallel, auth, verbose=False):
        self.uploaders = []
        self.max_parallel = max_parallel
        self.url = url
        self.auth = auth
        self.verbose = verbose

        self.cmd_base = ['curl',
                         '--fail',
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

        self.token = None
        self.token_expire_at = None
        self.token_endpoint = None

    def upload_dir(self, path, scan_first):
        print('Going to upload {} with {} threads to {}'.format(
            path, self.max_parallel, self.url))

        for file_path in self.find_files(path):
            self.cnt_expected += 1

        # FIXME: safety counter, abort after this many uploads (0 == disabled)
        debug_cnt = 0
        class DebugExc(Exception):
            def __init__(self):
                super().__init__('Debug exit')

        try:
            # FIXME: always verify that first file upload works
            # - for first file change max_parallel to 1
            # - validate there is no failure after it is done
            # - and then reset max_parallel to desired value
            # - only then continue with rest of files
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
        print('') # terminate inline progress report
        print('== Uploaded {total} files, with {failed} failures =='.format(
            total=self.cnt_total,
            failed=self.cnt_failed))

    def curl_or_wait(self, jsonfile):
        cmd = self.cmd_base[:]

        if self.auth:
            # token is added to cmd here, as ideally it should be obtained/refreshed
            # just here before upload
            cmd.append('--header')
            cmd.append('Authorization: Bearer {t}'.format(t=self.get_token()))

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

    def get_token(self):
        if self.have_valid_token():

            return self.token

        (cid, csec) = self.auth.split(':', 1)
        token_resp = self.curl_response(
            self.get_token_endpoint(),
            headers = ['Content-Type: application/x-www-form-urlencoded'],
            data = ['grant_type=client_credentials',
                    'client_id={}'.format(cid),
                    'client_secret={}'.format(csec)])
        token = json.loads(token_resp)
        if self.verbose:
            print(token)

        self.token = token['access_token']
        self.token_expire_at = int(time.time()) \
                + int(token['expires_in']) \
                - TcUpload.DEF_TOKEN_RESERVE_SEC

        return self.token

    def have_valid_token(self):
        now = time.monotonic()
        ##### left behind in case debug is needed
        # if self.verbose:
        #     print('have_valid_token: have expire_at {}'.format(
        #         self.token_expire_at))
        #     if self.token_expire_at is not None:
        #         print('have_valid_token: not expired {} > {} = {}'.format(
        #             self.token_expire_at,
        #             now,
        #             self.token_expire_at > now))

        return (self.token_expire_at is not None
                and self.token_expire_at > now)

    def get_token_endpoint(self):
        if self.token_endpoint is None:
            if self.verbose:
                print('// Detecting oidc endpoint ...')
            try:
                tpa_web_url = self.url.split('api/v2/')[0]
                src = self.curl_response(tpa_web_url)
                # cut string to rest after starting marker
                starter = 'window._env'
                src = src[src.index(starter) + len(starter):]
                # cut string to after first quote
                src = src[src.index('"') + 1:]
                # cut string to before next quote
                src = src[:src.index('"')]
                # decode dict from base64 encoded json string
                win_env = base64.b64decode(src)
                win_env = json.loads(win_env)
                oidc_server = win_env['OIDC_SERVER_URL']

                if self.verbose:
                    print('// Detecting token endpoint ...')
                # query oidc for config with token_endpoint
                oidc_cfg = self.curl_response(
                    '%s/.well-known/openid-configuration' % oidc_server)
                oidc_cfg = json.loads(oidc_cfg)

                self.token_endpoint = oidc_cfg['token_endpoint']
                if self.verbose:
                    print('// Token endpoint: {}'.format(self.token_endpoint))
            except ValueError as e:
                raise Exception('ERROR: Unable to detect oidc endpoint', e)
        return self.token_endpoint

    def curl_response(self, url, headers=None, data=None, timeout=60):
        headers = [] if headers is None else headers
        data = [] if data is None else data
        # wait for url response and return the body string
        cc = ['curl',
              '--fail',
              '--location',
              '--insecure']
        for h in headers:
            cc.append('-H')
            cc.append(h)
        for d in data:
            cc.append('--data-raw')
            cc.append(d)
        cc.append(url)

        cproc = subprocess.Popen(
            cc,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        if cproc.wait(timeout) != 0:
            print('ERROR: request for {} failed:'.format(url))
            self.print_cmd_err(cproc)
            raise Exception('curl_response failed to fetch data')
        elif self.verbose:
            self.print_cmd_err(cproc)


        return cproc.stdout.read()


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
                        self.print_cmd_err(uploader)
                    elif self.verbose:
                        self.print_cmd_err(uploader)
                    self.uploaders.remove(uploader)

    def print_cmd_err(self, cmd):
        print('') # terminate inline status update
        print(shlex.join(cmd.args))
        print(cmd.stderr.read())



def parse_args(args):
    p = argparse.ArgumentParser()
    p.add_argument('source_dir',
                   help='Source directory with (sbom/csaf) json files')
    p.add_argument('target_url',
                   help='Upload URL of Trustify API'
                   ' (with /api/v2/sbom or csaf)')
    p.add_argument('creds',
                   nargs='?',
                   default='',
                   help='user:password credentials for obtaining token'
                   ' for Trustify API (optional)')
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
    p.add_argument('-v', '--verbose',
                   action='store_true',
                   default=False,
                   help='Verbose mode for debugging')
    return p.parse_args(args)


if __name__ == '__main__':

    print("***Welcome to Trustification file uploader tool!***")
    tcu = None
    if len(sys.argv) >= 2:
        args = parse_args(sys.argv[1:])

        path = args.source_dir
        scan_first = args.scan_first

        tcu = TcUpload(
            url=args.target_url,
            max_parallel=args.max_parallel,
            auth=args.creds,
            verbose=args.verbose)
    else:
        scan_first = False
        path = input("Please enter the path to upload your SBOM or CSAF files from: ")  # Enter the files' path

        url = input("Please enter the server URL to upload the files to: ")   # Enter the remote server URL to upload files
        auth = input("Please enter the credentials for obtaining bearer token: ")  # Enter the bearer token of Trustification api server
        max_p = input("Please enter max parallel count [{}]: "
                      .format(TcUpload.DEF_PARALLEL))
        max_p = int(max_p if len(max_p) else TcUpload.DEF_PARALLEL)

        tcu = TcUpload(url=url, max_parallel=max_p, auth=auth)

    tcu.upload_dir(path, scan_first)

