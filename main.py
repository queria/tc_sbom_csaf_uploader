#!/usr/bin/env python
import cmd
import os
import random
import subprocess
import sys
import time


class TcUpload(cmd.Cmd):

    def __init__(self, url, max_parallel=3):
        self.uploaders = []
        self.max_parallel = max_parallel

        self.cmd_base = ['curl',
                         '-X', 'POST',
                         '--location',
                         '--insecure',
                         '--header', 'Content-Type: application/json',
                         '--header', 'Accept: application/json',
                         url,
                        ]

        self.cnt_total = 0
        self.cnt_failed = 0

    def upload_dir(self, path, token):
        folders = [path]

        print('Going to upload {} with {} threads'.format(
            path, self.max_parallel))

        # FIXME: safety counter, abort after this many uploads (0 == disabled)
        debug_cnt = 0
        class DebugExc(Exception):
            def __init__(self):
                super().__init__('Debug exit')

        try:
            for d in folders:
                for dentry in os.scandir(d):
                    if dentry.is_dir():
                        folders.append(dentry)
                    elif dentry.is_file():
                        self.curl_or_wait(dentry.path, token)
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

    def finalize(self):
        self.wait_for_parallel(for_all=True)
        print('== Uploaded {total} files, with {failed} failures =='.format(
            total=self.cnt_total,
            failed=self.cnt_failed))

    def curl_or_wait(self, jsonfile, token):
        cmd = self.cmd_base[:]

        if token:
            # token is added to cmd here, as ideally it should be obtained/refreshed
            # just here before upload
            cmd.append('--header')
            cmd.append('Authorization: Bearer {t}'.format(t=token))

        cmd.append('--upload-file')
        cmd.append(jsonfile)

        # FIXME: just for testing
        #cmd = ['ping', '-c3', 'localhost']

        self.wait_for_parallel()

        # print(cmd)
        print('\rUploaded {}'.format(self.cnt_total), end='', flush=True)

        self.uploaders.append(
            subprocess.Popen(
                cmd,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE))

    def wait_for_parallel(self, for_all=False):
        needed_max_count = 0 if for_all else (self.max_parallel - 1)
        # wait for uploads to finish
        while len(self.uploaders) > needed_max_count:
            time.sleep(0.05)
            # TODO: pop those which exited
            for uploader in self.uploaders:
                if uploader.poll() is not None:
                    # uploader returncode polling is non
                    self.cnt_total += 1
                    if uploader.returncode != 0:
                        self.cnt_failed += 1
                        # curl failed print errors:
                        print(' '.join(uploader.args))
                        print(uploader.stderr.read())
                    self.uploaders.remove(uploader)



        #print("Starting upload...")
        #for i in range(file_count):
        #    all_url = url + suffix
        #    if (files_in_folder[i].endswith('.json')) or (files_in_folder[i].endswith('.bz2')):
        #        command = 'curl -X POST' \
        #                  + ' --location ' + str(all_url) \
        #                  + ' -k --header ' \
        #                  + "'Authorization: Bearer " + str(token) + "'" \
        #                  + ' --upload-file ' + '"{' + str(path + files_in_folder[i]) + '}"' \
        #                  + ' --header ' + "'Content-Type: application/json" + "'"\
        #                  + ' --header ' + "'Accept: application/json" + "'"
        #        subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #        output = subprocess.check_output(['bash', '-c', command])
        #        print(output)
        #        i += 1
        #    else:
        #        bad_files = str(files_in_folder[i])
        #        print('Error: The file you are trying to upload called ' + "'" + bad_files + "'" + ' is not of .json type. Please upload only .json files')
        #        i += 1


if __name__ == '__main__':

    print("***Welcome to Trustification file uploader tool!***")
    if len(sys.argv) >= 2:
        if '--help' in sys.argv or len(sys.argv) < 3:
            print('{bin} <src/dir> <http_dest_url> [token]'
                  .format(bin=sys.argv[0]))
            sys.exit(0)
        path = sys.argv[1]
        url = sys.argv[2]
        try:
            token = sys.argv[3]
        except IndexError:
            token = ''
    else:
        path = input("Please enter the path to upload your SBOM or CSAF files from: ")  # Enter the files' path
        url = input("Please enter the server URL to upload the files to: ")   # Enter the remote server URL to upload files
        token = input("Please enter the bearer token: ")  # Enter the bearer token of Trustification api server

    TcUpload(url).upload_dir(path, token)

