"""
Test library.
"""

import difflib
import http.server
import inspect
import json
import os
import posixpath
import pprint
import re
import shlex
import shutil
import socketserver
import string
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
import zlib

from pathlib import Path
from uuid import uuid4


def ungzip_if_required(output):
    if isinstance(output, bytes) and output.startswith(b"\x1f\x8b"):
        return zlib.decompress(output, 16 + zlib.MAX_WBITS).decode('utf-8')

    return output


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class FileHTTPServerRequestHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        """Translate a /-separated PATH to the local filename syntax.

        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)

        """
        # abandon query parameters
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]
        path = posixpath.normpath(urllib.parse.unquote(path))
        words = path.split('/')
        words = [_f for _f in words if _f]
        path = self.rootPath
        for word in words:
            _, word = os.path.splitdrive(word)
            _, word = os.path.split(word)
            if word in (os.curdir, os.pardir):
                continue
            path = os.path.join(path, word)
        return path

    def log_message(self, format, *args):
        pass


class GPGFinder(object):
    """
    GnuPG binary discovery.
    """

    def __init__(self):
        self.gpg1 = self.find_gpg(["gpg1", "gpg"], "gpg (GnuPG) 1.")
        self.gpg2 = self.find_gpg(["gpg2", "gpg"], "gpg (GnuPG) 2.")

        self.gpg = self.gpg1
        if self.gpg is None:
            self.gpg = self.gpg2

        if self.gpg is None:
            raise Exception("GnuPG binary wasn't found")

    def find_gpg(self, executables, expected_version):
        for executable in executables:
            try:
                output = subprocess.check_output([executable, "--version"], text=True)
                if expected_version in output:
                    return executable
            except Exception:
                pass

        return None


class DotFinder(object):
    """
    dot binary discovery.
    """

    def __init__(self):
        self.dot = self.find_dot(["dot"])

    def find_dot(self, executables):
        for executable in executables:
            try:
                subprocess.check_output([executable, "-V"], text=True, stderr=subprocess.DEVNULL)
                return executable
            except Exception:
                pass

        return None


class BaseTest(object):
    """
    Base class for all tests.
    """

    skipTest = False
    longTest = False
    fixturePool = False
    fixturePoolCopy = False
    fixtureDB = False
    fixtureGpg = False
    fixtureWebServer = False
    requiresFTP = False
    requiresGPG1 = False
    requiresGPG2 = False
    requiresDot = False
    sortOutput = False
    debugOutput = False
    EtcdServer = None
    faketime = False

    aptlyDir = ".aptly"
    aptlyConfigFile = ".aptly.conf"
    expectedCode = 0
    databaseType = ""
    databaseUrl = ""

    configOverride = {}
    environmentOverride = {}

    fixtureDBDir = os.path.join(os.environ["HOME"], "aptly-fixture-db")
    fixturePoolDir = os.path.join(os.environ["HOME"], "aptly-fixture-pool")
    fixtureGpgKeys = ["debian-archive-keyring.gpg",
                      "ubuntu-archive-keyring.gpg",
                      "launchpad.key",
                      "flat.key",
                      "pagerduty.key",
                      "nvidia.key",
                      "jenkins.key"]

    outputMatchPrepare = None

    captureResults = False

    gpgFinder = GPGFinder()
    dotFinder = DotFinder()

    def test(self):
        self.prepare()
        try:
            self.run()
            self.check()
        except Exception as exc:
            if self.debugOutput:
                print(f"API log:\n{self.debug_output()}")
            raise exc
        finally:
            self.teardown()

    def prepare_remove_all(self):
        if os.path.exists(os.path.join(os.environ["HOME"], self.aptlyDir)):
            shutil.rmtree(os.path.join(os.environ["HOME"], self.aptlyDir))
        if os.path.exists(os.path.join(os.environ["HOME"], self.aptlyConfigFile)):
            os.remove(os.path.join(os.environ["HOME"], self.aptlyConfigFile))
        if os.path.exists(os.path.join(os.environ["HOME"], ".gnupg", "aptlytest.gpg")):
            os.remove(os.path.join(
                os.environ["HOME"], ".gnupg", "aptlytest.gpg"))

    def prepare_default_config(self):
        databaseBackend = {
            "type": self.databaseType,
            "url": self.databaseUrl,
        }

        cfg = {
            "rootDir": f"{os.environ['HOME']}/{self.aptlyDir}",
            "downloadConcurrency": 4,
            "downloadSpeedLimit": 0,
            "downloadRetries": 5,
            "databaseOpenAttempts": 10,
            "architectures": [],
            "dependencyFollowSuggests": False,
            "dependencyFollowRecommends": False,
            "dependencyFollowAllVariants": False,
            "dependencyFollowSource": False,
            "gpgDisableVerify": False,
            "gpgDisableSign": False,
            "ppaDistributorID": "ubuntu",
            "ppaCodename": "",
            "enableMetricsEndpoint": True,
            "logLevel": "debug",
            "logFormat": "default",
            "serveInAPIMode": True,
            "databaseBackend": databaseBackend,
        }
        if self.requiresGPG1:
            cfg["gpgProvider"] = "gpg1"
        elif self.requiresGPG2:
            cfg["gpgProvider"] = "gpg2"
        cfg.update(**self.configOverride)
        f = open(os.path.join(os.environ["HOME"], self.aptlyConfigFile), "w")
        f.write(json.dumps(cfg))
        f.close()

    def fixture_available(self):
        if self.fixturePool and not os.path.exists(self.fixturePoolDir):
            return False
        if self.fixtureDB and not os.path.exists(self.fixtureDBDir):
            return False
        if self.requiresFTP and os.environ.get('NO_FTP_ACCESS', '') == 'yes':
            return False
        if self.requiresGPG1 and self.gpgFinder.gpg1 is None:
            return False
        if self.requiresGPG2 and self.gpgFinder.gpg2 is None:
            return False
        if self.requiresDot and self.dotFinder.dot is None:
            return False

        return True

    def prepare_fixture(self):
        if self.fixturePool:
            os.makedirs(os.path.join(os.environ["HOME"], self.aptlyDir), 0o755)
            os.symlink(self.fixturePoolDir, os.path.join(
                os.environ["HOME"], self.aptlyDir, "pool"))

        if self.fixturePoolCopy:
            os.makedirs(os.path.join(os.environ["HOME"], self.aptlyDir), 0o755)
            shutil.copytree(self.fixturePoolDir, os.path.join(
                os.environ["HOME"], self.aptlyDir, "pool"), ignore=shutil.ignore_patterns(".git"))

        if self.databaseType == "etcd":
            if not os.path.exists("/tmp/aptly-etcd"):
                self.run_cmd([os.path.join(os.path.dirname(inspect.getsourcefile(BaseTest)), "t13_etcd/install-etcd.sh")])

        if self.fixtureDB and self.databaseType != "etcd":
            shutil.copytree(self.fixtureDBDir, os.path.join(os.environ["HOME"], self.aptlyDir, "db"))

        if self.databaseType == "etcd":
            if self.EtcdServer:
                self.shutdown_etcd()

            # remove existing database
            if os.path.exists("/tmp/aptly-etcd-data"):
                shutil.rmtree("/tmp/aptly-etcd-data")

            if self.fixtureDB:
                print("import etcd")
                self.run_cmd(["/tmp/aptly-etcd/etcdctl", "--data-dir=/tmp/aptly-etcd-data", "snapshot", "restore", os.path.join(os.environ["HOME"], "etcd.db")])

            print("starting etcd")
            self.EtcdServer = self._start_process([os.path.join(os.path.dirname(inspect.getsourcefile(BaseTest)), "t13_etcd/start-etcd.sh")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if self.fixtureWebServer:
            self.webServerUrl = self.start_webserver(os.path.join(os.path.dirname(inspect.getsourcefile(self.__class__)),
                                                                  self.fixtureWebServer))

        if self.requiresGPG2 or self.gpgFinder.gpg2:
            self.run_cmd([
                self.gpgFinder.gpg2, "--import",
                os.path.join(os.path.dirname(inspect.getsourcefile(BaseTest)), "files") + "/aptly.sec"], expected_code=None)

        if self.fixtureGpg:
            self.run_cmd([self.gpgFinder.gpg, "--no-default-keyring", "--trust-model", "always", "--batch", "--keyring", "aptlytest.gpg", "--import"] +
                         [os.path.join(os.path.dirname(inspect.getsourcefile(BaseTest)), "files", key) for key in self.fixtureGpgKeys])
            self.run_cmd(["chmod", "400", os.path.join(os.environ["HOME"], ".gnupg/aptlytest.gpg")])

        if hasattr(self, "fixtureCmds"):
            for cmd in self.fixtureCmds:
                output = self.run_cmd(cmd)
                print("fixture Output:\n")
                for line in output.split("\n"):
                    print(f"    {line}")

    def sort_lines(self, output):
        return "\n".join(sorted(self.ensure_utf8(output).split("\n")))

    def run(self):
        output = self.run_cmd(self.runCmd, self.expectedCode)
        self.output = self.output_processor(output)

    def _start_process(self, command, stderr=subprocess.STDOUT, stdout=None):
        if isinstance(command, str):
            params = {
                'files': os.path.join(os.path.dirname(inspect.getsourcefile(BaseTest)), "files"),
                'changes': os.path.join(os.path.dirname(inspect.getsourcefile(BaseTest)), "changes"),
                'udebs': os.path.join(os.path.dirname(inspect.getsourcefile(BaseTest)), "udebs"),
                'testfiles': os.path.join(os.path.dirname(inspect.getsourcefile(self.__class__)), self.__class__.__name__),
                'aptlyroot': os.path.join(os.environ["HOME"], self.aptlyDir),
            }
            if self.fixtureWebServer:
                params['url'] = self.webServerUrl

            command = string.Template(command).substitute(params)
            print(f"running command: {command}\n")
            command = shlex.split(command)

        if command[0] == "aptly":
            aptly_testing_bin = Path(__file__).parent / ".." / "aptly.test"
            command = [str(aptly_testing_bin), f"-test.coverprofile={Path(self.coverage_dir) / self.__class__.__name__}-{uuid4()}.out", *command[1:]]

        if self.faketime:
            command = ["faketime", os.environ.get("TEST_FAKETIME", "2025-01-02 03:04:05")] + command

        environ = os.environ.copy()
        environ["LC_ALL"] = "C"
        environ.update(self.environmentOverride)
        return subprocess.Popen(command, stderr=stderr, stdout=stdout, env=environ)

    def run_cmd(self, command, expected_code=0):
        proc = self._start_process(command, stdout=subprocess.PIPE)
        raw_output, _ = proc.communicate()

        raw_output = raw_output.decode("utf-8", errors='replace')

        returncodes = [proc.returncode]
        is_aptly_command = False
        if isinstance(command, str):
            is_aptly_command = command.startswith("aptly")

        if isinstance(command, list):
            is_aptly_command = command[0] == "aptly"

        if is_aptly_command:
            # remove the last two rows as go tests always print PASS/FAIL and coverage in those
            # two lines. This would otherwise fail the tests as they would not match gold
            matches = re.findall(r"((.|\n)*)EXIT: (\d)\n.*\ncoverage: .*", raw_output)
            if not matches:
                raise Exception("no matches found in command output '%s'" % raw_output)

            output, _, returncode = matches[0]
            returncodes.append(int(returncode))
        else:
            output = raw_output

        if expected_code is not None:
            if expected_code not in returncodes:
                raise Exception("command expected to return %d, but returned %d: \n%s" % (
                    expected_code, proc.returncode, raw_output))
        return output

    def gold_processor(self, gold):
        return gold

    def output_processor(self, output):
        return output

    def expand_environ(self, gold):
        return string.Template(gold).substitute(os.environ)

    def get_gold_filename(self, gold_name="gold"):
        return os.path.join(os.path.dirname(inspect.getsourcefile(self.__class__)), self.__class__.__name__ + "_" + gold_name)

    def get_gold(self, gold_name="gold"):
        return self.gold_processor(open(self.get_gold_filename(gold_name), "r").read())

    def strip_retry_lines(self, s):
        for prefix in (
                'Following redirect',
                'Error downloading',
                'Retrying',
        ):
            s = re.sub(r'{}.*\n'.format(prefix), '', s)
        return s

    def check_output(self):
        gold_file = self.get_gold_filename()
        print(f"Verifying gold file: {gold_file}")
        try:
            self.verify_match(self.get_gold(), self.output,
                              match_prepare=self.outputMatchPrepare)
        except Exception:  # noqa: E722
            if self.captureResults:
                if self.outputMatchPrepare is not None:
                    self.output = self.outputMatchPrepare(self.output)
                with open(self.get_gold_filename(), "w") as f:
                    f.write(self.output)
            else:
                raise

    def check_cmd_output(self, command, gold_name, match_prepare=None, expected_code=0):
        output = self.run_cmd(command, expected_code=expected_code)
        try:
            self.verify_match(self.get_gold(gold_name), output, match_prepare)
        except:  # noqa: E722
            if self.captureResults:
                if match_prepare is not None:
                    output = match_prepare(output)
                with open(self.get_gold_filename(gold_name), "w") as f:
                    f.write(output)
            else:
                raise

    def write_file(self, path, content):
        full_path = os.path.join(os.environ["HOME"], ".aptly", path)

        if not os.path.exists(os.path.dirname(full_path)):
            os.makedirs(os.path.dirname(full_path), 0o755)

        with open(full_path, "w") as f:
            f.write(content)

    def read_file(self, path, mode=''):
        with open(os.path.join(os.environ["HOME"], self.aptlyDir, path), "r" + mode) as f:
            return f.read()

    def delete_file(self, path):
        os.unlink(os.path.join(os.environ["HOME"], self.aptlyDir, path))

    def check_file_contents(self, path, gold_name, match_prepare=None, mode='', ensure_utf8=True):
        contents = self.read_file(path, mode=mode)
        try:

            self.verify_match(self.get_gold(gold_name),
                              contents, match_prepare=match_prepare,
                              ensure_utf8=ensure_utf8)
        except:  # noqa: E722
            if self.captureResults:
                if match_prepare is not None:
                    contents = match_prepare(contents)
                with open(self.get_gold_filename(gold_name), "w") as f:
                    f.write(contents)
            else:
                raise

    def check_file(self):
        contents = open(self.checkedFile, "r").read()
        try:
            self.verify_match(self.get_gold(), contents)
        except:  # noqa: E722
            if self.captureResults:
                with open(self.get_gold_filename(), "w") as f:
                    f.write(contents)
            else:
                raise

    def check_exists(self, path):
        if not os.path.exists(os.path.join(os.environ["HOME"], self.aptlyDir, path)):
            raise Exception("path %s doesn't exist" % (path, ))

    def check_not_exists(self, path):
        if os.path.exists(os.path.join(os.environ["HOME"], self.aptlyDir, path)):
            raise Exception("path %s exists" % (path, ))

    def check_file_not_empty(self, path):
        if os.stat(os.path.join(os.environ["HOME"], self.aptlyDir, path))[6] == 0:
            raise Exception("file %s is empty" % (path, ))

    def check_equal(self, a, b):
        if a != b:
            self.verify_match(a, b, match_prepare=pprint.pformat)

    def check_ge(self, a, b):
        if not a >= b:
            raise Exception("%s is not greater or equal to %s" % (a, b))

    def check_gt(self, a, b):
        if not a > b:
            raise Exception("%s is not greater to %s" % (a, b))

    def check_in(self, item, l):
        if item not in l:
            raise Exception("expected item: %r\nnot found in: %r" % (item, l))

    def check_not_in(self, item, l):
        if item in l:
            raise Exception("unexpected item: %r\n found in: %r" % (item, l))

    def check_subset(self, a, b):
        diff = ''
        for k, v in list(a.items()):
            if k not in b:
                diff += "unexpected key '%s'\n" % (k,)
            elif b[k] != v:
                diff += "wrong value '%s' for key '%s', expected '%s'\n" % (
                    v, k, b[k])
        if diff:
            raise Exception("content subset doesn't match:\n" + diff)

    def ensure_utf8(self, a):
        if isinstance(a, bytes):
            return a.decode('utf-8')
        return a

    def verify_match(self, gold, orig, match_prepare=None, ensure_utf8=True):
        output = orig
        if ensure_utf8:
            gold = self.ensure_utf8(gold)
            output = self.ensure_utf8(output)

        if match_prepare is not None:
            gold = match_prepare(gold)
            output = match_prepare(output)

        # sort if requested
        if self.sortOutput:
            gold = self.sort_lines(gold)
            output = self.sort_lines(output)

        # strip trailing whitespace and newlines
        gold = gold.strip()
        output = output.strip()

        if gold != output:
            diff = "".join(difflib.unified_diff(
                [l + "\n" for l in gold.split("\n")], [l + "\n" for l in output.split("\n")]))
            raise Exception("content doesn't match:\n" + diff + "\n\nOutput:\n" + orig + "\n")

    check = check_output

    def prepare(self):
        self.prepare_remove_all()
        self.prepare_default_config()
        self.prepare_fixture()

    def teardown(self):
        if self.EtcdServer:
            self.shutdown_etcd()

    def start_webserver(self, directory):
        FileHTTPServerRequestHandler.rootPath = directory
        self.webserver = ThreadedTCPServer(
            ("localhost", 0), FileHTTPServerRequestHandler)

        server_thread = threading.Thread(target=self.webserver.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        return "http://%s:%d/" % self.webserver.server_address

    def shutdown(self):
        if hasattr(self, 'webserver'):
            self.shutdown_webserver()
        if self.EtcdServer:
            self.shutdown_etcd()

    def shutdown_webserver(self):
        self.webserver.shutdown()

    def shutdown_etcd(self):
        print("stopping etcd")
        self.EtcdServer.terminate()
        self.EtcdServer.wait()
        self.EtcdServer = None

    @classmethod
    def shutdown_class(cls):
        pass
