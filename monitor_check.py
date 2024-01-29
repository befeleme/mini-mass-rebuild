import aiohttp
import asyncio
import bugzilla
import logging
import re
import sys
from urllib.parse import urlencode, quote, unquote
from textwrap import dedent
import webbrowser

import click
from click import secho
from collections import Counter

import dnf
from anytree import Node, RenderTree, findall_by_attr, LoopError

from copr.v3 import Client

COPR = '@python', 'python3.13'
COPR_STR = '{}/{}'.format(*COPR)
COPR_STR_G = '{}/{}'.format(COPR[0].replace('@', 'g/'), COPR[1])

MONITOR = f'https://copr.fedorainfracloud.org/coprs/{COPR_STR_G}/monitor/'
INDEX = f'https://copr-be.cloud.fedoraproject.org/results/{COPR_STR}/fedora-rawhide-x86_64/{{build:08d}}-{{package}}/'  # keep the slash
PDC = 'https://pdc.fedoraproject.org/rest_api/v1/component-branches/?name=rawhide&global_component={package}'
PACKAGE = re.compile(fr'<a href="/coprs/{COPR_STR_G}/package/([^/]+)/">')
BUILD = re.compile(fr'<a href="/coprs/{COPR_STR_G}/build/([^/]+)/">')
RESULT = re.compile(r'<span class="build-([^"]+)"')
RPM_FILE = "<td class='t'>RPM File</td>"
TAG = 'f40'
# copr bug: build.log isn't properly populated
# TODO: rework to use builder-live.log.gz or wait for https://github.com/fedora-copr/copr/issues/2961
LIMIT = 30
BUGZILLA = 'bugzilla.redhat.com'
BZ_PAGE_SIZE = 20
TRACKER = 2244836  # PYTHON3.13
RAWHIDE = 2231791  # F40FTBFS
LOGLEVEL = logging.WARNING

DNF_CACHEDIR = '_dnf_cache_dir'
ARCH = 'x86_64'

EXPLANATION = {
    'red': 'probably FTBFS',
    'blue': 'probably blocked',
    'yellow': 'reported',
    'green': 'retired',
    'cyan': 'excluded from bug filing',
    'magenta': 'copr timeout or repo 404',
}

# FTBS packages for which we don't open bugs (yet)
EXCLUDE = {
    "fapolicy-analyzer": "unrelated for now",
    "python-zbase32": "depends on retired pyutil",
    "python-apsw": "version is set by the set of if-clauses in the spec",
}

REASONS = {
    "implicit declaration of PyEval_InitThreads": {
        "regex": r"(.*error:.*(PyEval_InitThreads|PyEval_ThreadsInitialized).*)",
        "long_description": """{MATCH}
        According to https://docs.python.org/3.13/whatsnew/3.13.html:

        Remove PyEval_InitThreads() and PyEval_ThreadsInitialized() functions, deprecated in Python 3.9.
        Since Python 3.7, Py_Initialize() always creates the GIL:
        calling PyEval_InitThreads() did nothing and PyEval_ThreadsInitialized() always returned non-zero.
        (Contributed by Victor Stinner in https://github.com/python/cpython/issues/105182.)
        """,
        "short_description": "error: implicit declaration of function ‘PyEval_InitThreads’",
    },
    "_PyThreadState_UncheckedGet is now public": {
        "regex": r"(.*error:.*_PyThreadState_UncheckedGet.*)",
        "long_description": """{MATCH}

        According to https://docs.python.org/3.13/whatsnew/3.13.html a new public function has been added:

        Add PyThreadState_GetUnchecked() function: similar to PyThreadState_Get(), but don’t kill the process with a fatal error if it is NULL.
        The caller is responsible to check if the result is NULL.
        Previously, the function was private and known as _PyThreadState_UncheckedGet().
        (Contributed by Victor Stinner in gh-108867.)
        """,
        "short_description": "",
    },
    "time.h-sys/select.h-sys/time.h": {
        "regex": r"(.*error:.*(gettimeofday|clock|gmtime|select|futimes|setitimer).*)",
        "long_description": """{MATCH}
        According to https://docs.python.org/3.13/whatsnew/3.13.html:

        Python.h no longer includes these standard header files: <time.h>, <sys/select.h> and <sys/time.h>.
        If needed, they should now be included explicitly.
        For example, <time.h> provides the clock() and gmtime() functions, <sys/select.h> provides the select() function,
        and <sys/time.h> provides the futimes(), gettimeofday() and setitimer() functions.
        (Contributed by Victor Stinner in gh-108765.)
        """,
        "short_description": "error: Missing declaration of <time.h>, <sys/select.h> or <sys/time.h> module",
    },
    "unistd.h": {
        "regex": r"(.*error:.*(getpid|read|write|close|isatty|lseek|getpid|getcwd|sysconf|getpagesize|dup|access).*)",
        "long_description": """{MATCH}
        According to https://docs.python.org/3.13/whatsnew/3.13.html:

        Python.h no longer includes the <unistd.h> standard header file.
        If needed, it should now be included explicitly.
        For example, it provides the functions: read(), write(), close(), isatty(), lseek(), getpid(), getcwd(), sysconf() and getpagesize().
        As a consequence, _POSIX_SEMAPHORES and _POSIX_THREADS macros are no longer defined by Python.h.
        The HAVE_UNISTD_H and HAVE_PTHREAD_H macros defined by Python.h can be used to decide if <unistd.h> and <pthread.h> header files can be included.
        (Contributed by Victor Stinner in gh-108765.)
        """,
        "short_description": "Missing <unistd.h> declaration",
    },
    "_PyLong_AsByteArray or _PyLong_FromByteArray or _Py_IDENTIFIER": {
        "regex": r"(.*error:.*(_PyLong_AsByteArray|_PyLong_FromByteArray|_Py_IDENTIFIER|_PyLong_New).*)",
        "long_description": """{MATCH}

        This function has been removed from Python 3.13.
        The detailed list of the removed private C API functions can be found here:
        https://github.com/python/cpython/issues/106320
        """,
        "short_description": "",
    },
    "initialization functions": {
        "regex": r"(.*error:.*(Py_SetProgramName|Py_SetPythonHome|Py_SetStandardStreamEncoding|_Py_SetProgramFullPath|Py_SetPath|PySys_SetPath|PySys_SetArgv|PySys_SetArgvEx|PySys_HasWarnOptions|PySys_AddXOption|PySys_AddWarnOption|PySys_AddWarnOptionUnicode).*)",
        "long_description": """{MATCH}

        According to https://docs.python.org/3.13/whatsnew/3.13.html:
        Remove the following old functions to configure the Python initialization, deprecated in Python 3.11:
            PySys_AddWarnOptionUnicode(): use PyConfig.warnoptions instead.
            PySys_AddWarnOption(): use PyConfig.warnoptions instead.
            PySys_AddXOption(): use PyConfig.xoptions instead.
            PySys_HasWarnOptions(): use PyConfig.xoptions instead.
            PySys_SetArgvEx(): set PyConfig.argv instead.
            PySys_SetArgv(): set PyConfig.argv instead.
            PySys_SetPath(): set PyConfig.module_search_paths instead.
            Py_SetPath(): set PyConfig.module_search_paths instead.
            Py_SetProgramName(): set PyConfig.program_name instead.
            Py_SetPythonHome(): set PyConfig.home instead.
            Py_SetStandardStreamEncoding(): set PyConfig.stdio_encoding instead, and set also maybe PyConfig.legacy_windows_stdio (on Windows).
            _Py_SetProgramFullPath(): set PyConfig.executable instead.
        """,
        "short_description": "error: implicit declaration of function XXX",
    },
    "Py_TRASHCAN_SAFE": {
        "regex": r"(.*error: .*(Py_TRASHCAN_SAFE_BEGIN|Py_TRASHCAN_SAFE_END).*)",
        "long_description": """{MATCH}

        According to https://docs.python.org/3.13/whatsnew/3.13.html:
        Remove the old trashcan macros Py_TRASHCAN_SAFE_BEGIN and Py_TRASHCAN_SAFE_END.
        They should be replaced by the new macros Py_TRASHCAN_BEGIN and Py_TRASHCAN_END.
        The new macros were added in Python 3.8 and the old macros were deprecated in Python 3.11.
        (Contributed by Irit Katriel in gh-105111.)
        """,
        "short_description": "",
    },
    "importlib.resources": {
        "regex": r"(ImportError: cannot import name '(.*?)' from 'importlib.resources'|AttributeError: module 'importlib.resources' has no attribute '(.*?)')",
        "long_description": """{MATCH}

        The deprecated importlib.resources methods were removed from Python 3.13:
        - contents()
        - is_resource()
        - open_binary()
        - open_text()
        - path()
        - read_binary()
        - read_text()
        Use files() instead. Refer to importlib-resources: Migrating from Legacy for migration advice.
        https://importlib-resources.readthedocs.io/en/latest/using.html#migrating-from-legacy
        """,
        "short_description": "",
    },
    "telnetlib": {
        "regex": r"(ModuleNotFoundError: No module named 'telnetlib')",
        "long_description": """{MATCH}

        According to https://docs.python.org/3.13/whatsnew/3.13.html:
        PEP 594: Remove the telnetlib module, deprecated in Python 3.11: use the projects telnetlib3 or Exscript instead.
        (Contributed by Victor Stinner in gh-104773.)
        """,
        "short_description": "",
    },
    "crypt": {
        "regex": r"(ModuleNotFoundError: No module named 'crypt')",
        "long_description": """{MATCH}

        According to https://docs.python.org/3.13/whatsnew/3.13.html:

        PEP 594: Remove the crypt module and its private _crypt extension, deprecated in Python 3.11.
        The hashlib module is a potential replacement for certain use cases.
        Otherwise, the following PyPI projects can be used:
        - bcrypt: Modern password hashing for your software and your servers.
        - passlib: Comprehensive password hashing framework supporting over 30 schemes.
        - argon2-cffi: The secure Argon2 password hashing algorithm.
        - legacycrypt: Wrapper to the POSIX crypt library call and associated functionality.
        (Contributed by Victor Stinner in gh-104773.)
        """,
        "short_description": "",
    },
    "locale.resetlocale": {
        "regex": r"(ImportError: cannot import name 'resetlocale' from 'locale')",
        "long_description": """{MATCH}

        Remove locale.resetlocale() function deprecated in Python 3.11: use locale.setlocale(locale.LC_ALL, "") instead.
        (Contributed by Victor Stinner in gh-104783.)
        """,
        "short_description": "",
    },
    "implicit declaration of PyEval_AcquireLock or PyEval_ReleaseLock": {
        "regex": r"(.*error:.*(PyEval_AcquireLock|PyEval_ReleaseLock).*)",
        "long_description": """{MATCH}

        According to https://docs.python.org/3.13/whatsnew/3.13.html:

        Remove PyEval_AcquireLock() and PyEval_ReleaseLock() functions, deprecated in Python 3.2.
        They didn’t update the current thread state. They can be replaced with:
            - PyEval_SaveThread() and PyEval_RestoreThread();
            - low-level PyEval_AcquireThread() and PyEval_RestoreThread();
            - or PyGILState_Ensure() and PyGILState_Release().
        (Contributed by Victor Stinner in gh-105182.)
        """,
        "short_description": "",
    },
    "implicit declaration of PyEval_CallObject or PyEval_CallObjectWithKeywords": {
        "regex": r"(.*error:.*(PyEval_CallObject|PyEval_CallObjectWithKeywords).*)",
        "long_description": """{MATCH}

        According to https://docs.python.org/3.13/whatsnew/3.13.html:

        Remove PyEval_CallObject(), PyEval_CallObjectWithKeywords(): use PyObject_CallNoArgs() or PyObject_Call() instead.
        Warning: PyObject_Call() positional arguments must be a tuple and must not be NULL,
        keyword arguments must be a dict or NULL, whereas removed functions checked arguments type and accepted NULL positional and keyword arguments.
        To replace PyEval_CallObjectWithKeywords(func, NULL, kwargs) with PyObject_Call(),
        pass an empty tuple as positional arguments using PyTuple_New(0).
        """,
        "short_description": "",
    },
    "ctype.h": {
        "regex": r"(.*include.*ctype\.h.*)",
        "long_description": """{MATCH}

        According to https://docs.python.org/3.13/whatsnew/3.13.html:

        Python.h no longer includes the <ctype.h> standard header file.
        If needed, it should now be included explicitly.
        For example, it provides isalpha() and tolower() functions which are locale dependent.
        Python provides locale independent functions, like Py_ISALPHA() and Py_TOLOWER().
        (Contributed by Victor Stinner in gh-108765.)
        """,
        "short_description": "Missing <ctype.h> declaration",
    },
    "no cgi": {
        "regex": r"(ModuleNotFoundError: No module named \'cgi\')",
        "long_description": """{MATCH}
        According to https://docs.python.org/3.13/whatsnew/3.13.html module cgi was removed:

        PEP 594: Remove the cgi and cgitb modules, deprecated in Python 3.11.

        cgi.FieldStorage can typically be replaced with urllib.parse.parse_qsl() for GET and HEAD requests, and the email.message module or multipart PyPI project for POST and PUT.

        cgi.parse() can be replaced by calling urllib.parse.parse_qs() directly on the desired query string, except for multipart/form-data input, which can be handled as described for cgi.parse_multipart().

        cgi.parse_multipart() can be replaced with the functionality in the email package (e.g. email.message.EmailMessage and email.message.Message) which implements the same MIME RFCs, or with the multipart PyPI project.

        cgi.parse_header() can be replaced with the functionality in the email package, which implements the same MIME RFCs. For example, with email.message.EmailMessage:

        from email.message import EmailMessage
        msg = EmailMessage()
        msg['content-type'] = 'application/json; charset="utf8"'
        main, params = msg.get_content_type(), msg['content-type'].params

        (Contributed by Victor Stinner in gh-104773.)
        """,
        "short_description": "ModuleNotFoundError: No module named 'cgi'",
    },
    "no pipes": {
        "regex": r"(ModuleNotFoundError: No module named \'pipes\')",
        "long_description": """{MATCH}
        According to https://docs.python.org/3.13/whatsnew/3.13.html module pipes was removed:

        PEP 594: Remove the pipes module, deprecated in Python 3.11: use the subprocess module instead.
        (Contributed by Victor Stinner in gh-104773.)
        """,
        "short_description": "ModuleNotFoundError: No module named 'pipes'",
    },
    "no tkinter.tix": {
        "regex": r"(ModuleNotFoundError: No module named \'tkinter\.tix\')",
        "long_description": """{MATCH}
        According to https://docs.python.org/3.13/whatsnew/3.13.html:

        Remove the tkinter.tix module, deprecated in Python 3.6.
        The third-party Tix library which the module wrapped is unmaintained.
        (Contributed by Zachary Ware in gh-75552.)
        """,
        "short_description": "ModuleNotFoundError: No module named 'tkinter.tix'",
    },
    "'Logger' object has no attribute 'warn'": {
        "regex": r"(\'Logger\' object has no attribute \'warn\'|AttributeError: module 'logging' has no attribute 'warn')",
        "long_description": """{MATCH}
        According to https://docs.python.org/3.13/whatsnew/3.13.html:

        logging: Remove undocumented and untested Logger.warn() and LoggerAdapter.warn() methods and logging.warn() function.
        Deprecated since Python 3.3, they were aliases to the logging.Logger.warning() method,
        logging.LoggerAdapter.warning() method and logging.warning() function.
        (Contributed by Victor Stinner in gh-105376.)
        """,
        "short_description": "",
    },
    "unittest": {
        "regex": r"(AttributeError: module \'unittest\' has no attribute \'(makeSuite|findTestCases|getTestCaseNames)\')",
        "long_description": """{MATCH}
        According to https://docs.python.org/3.13/whatsnew/3.13.html:

        Removed the following unittest functions, deprecated in Python 3.11:
        - unittest.findTestCases()
        - unittest.makeSuite()
        - unittest.getTestCaseNames()
        """,
        "short_description": "AttributeError: module 'unittest' has no attribute XXX",
    },
    "segfault": {
        # Segfault detection is quite noisy, especially if we do not want to report it this way. I temporarily disabled it with X in regex.
        "regex": r"XSegmentation fault",
        "long_description": """ DO NOT REPORT THIS """,
        "short_description": """ DO NOT REPORT THIS """,
    },
}

logger = logging.getLogger('monitor_check')

BZAPI = bugzilla.Bugzilla(BUGZILLA)

def _bugzillas():
    query = BZAPI.build_query(product='Fedora')
    query['blocks'] = [TRACKER, RAWHIDE]
    query['limit'] = BZ_PAGE_SIZE
    query['offset'] = 0
    results = []
    while len(partial := BZAPI.query(query)) == BZ_PAGE_SIZE:
        results += partial
        query['offset'] += BZ_PAGE_SIZE
    results += partial
    return [b for b in sorted(results, key=lambda b: -b.id)
            if b.resolution != 'DUPLICATE']


async def bugzillas():
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _bugzillas)

def _copr():
    client = Client.create_from_config_file()
    packages = client.package_proxy.get_list(ownername=COPR[0], projectname=COPR[1], with_latest_build=True)
    return packages

async def copr():
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _copr)

async def fetch(session, url, http_semaphore, *, json=False):
    retry = False
    async with http_semaphore:
        logger.debug('fetch %s', url)
        try:
            async with session.get(url) as response:
                # copr sometimes does not rename the logs
                # https://pagure.io/copr/copr/issue/1648
                if response.status == 404 and url.endswith('.gz'):
                    url = url[:-3]
                    retry = True
                elif json:
                    return await response.json()
                else:
                    return await response.text('utf-8')
        except (aiohttp.client_exceptions.ServerDisconnectedError, aiohttp.client_exceptions.ClientConnectorError):
            await asyncio.sleep(1)
            retry = True
    if retry:
        return await fetch(session, url, http_semaphore, json=json)


async def length(session, url, http_semaphore):
    retry = False
    async with http_semaphore:
        logger.debug('length %s', url)
        try:
            async with session.head(url) as response:
                return int(response.headers.get('content-length'))
        except (aiohttp.client_exceptions.ClientConnectorError, aiohttp.client_exceptions.ServerDisconnectedError):
            await asyncio.sleep(1)
            retry = True
    if retry:
        return await length(session, url, http_semaphore)

async def is_cmake(session, url, http_semaphore):
    try:
        content = await fetch(session, url, http_semaphore)
    except aiohttp.client_exceptions.ClientPayloadError:
        logger.debug('broken content %s', url)
        return False
    make = 'No targets specified and no makefile found.' in content
    cmake = '/usr/bin/cmake' in content
    return make and cmake


async def is_blue(session, url, http_semaphore):
    try:
        content = await fetch(session, url, http_semaphore)
    except aiohttp.client_exceptions.ClientPayloadError:
        logger.debug('broken content %s', url)
        return False
    return 'but none of the providers can be installed' in content


async def is_repo_404(session, url, http_semaphore):
    try:
        content = await fetch(session, url, http_semaphore)
    except aiohttp.client_exceptions.ClientPayloadError:
        logger.debug('broken content %s', url)
        return False
    return content.count('Librepo error: Yum repo downloading error') >= 3


async def is_timeout(session, url, http_semaphore):
    try:
        content = await fetch(session, url, http_semaphore)
    except aiohttp.client_exceptions.ClientPayloadError:
        logger.debug('broken content %s', url)
        return False
    return 'Copr timeout => sending INT' in content


async def guess_reason(session, url, http_semaphore):
    try:
        content = await fetch(session, url, http_semaphore)
    except aiohttp.client_exceptions.ClientPayloadError:
        logger.debug('broken content %s', url)
        return False
    for reason in REASONS.values():
        match = re.search(reason["regex"], content)
        if match:
            return {
                "long_description": reason["long_description"].format(MATCH=match.group()),
                "short_description": reason.get("short_description") or match.group(),
            }
    return None

async def guess_missing_dependency(session, package, build, http_semaphore, fg, bugs):
    url = builderlive_link(package, build)
    try:
        content = await fetch(session, url, http_semaphore)
    except aiohttp.client_exceptions.ClientPayloadError:
        logger.debug('broken content %s', url)
        return False
    patterns = [
        r"Problem.*?: package (.*?) requires python\(abi\) = 3\.12",
        r"package (.*?) requires .*?, but none of the providers can be installed",
        r"Status code: (.*?) for",
    ]
    if fg == 'yellow':
        yellow_pkgs.append(package)
    elif fg == 'blue':
        blue_pkgs.append(package)
    match_found = False
    for pattern in patterns:
        match = re.findall(pattern, content)
        if match:
            match_found == True
            match = list(set(match))
            for broken_pkg in match:
                broken_srpm = "404"
                if broken_pkg != "404":
                    broken_srpm = source_name(broken_pkg)
                if broken_srpm not in missing_dependencies:
                    missing_dependencies[broken_srpm] = []
                    missing_dependencies[broken_srpm].append(package)
                    # Uncomment this if you want to set bugzilla blockers
                    # bugzilla_set_blockers(bugs, broken_srpm, package)
                else:
                    if package not in missing_dependencies[broken_srpm]:
                        missing_dependencies[broken_srpm].append(package)
                        # Uncomment this if you want to set bugzilla blockers
                        # bugzilla_set_blockers(bugs, broken_srpm, package)
    if not match_found:
        missing_dependencies['match_failed'].append(package)

def bugzilla_set_blockers(bugs, broken_srpm, package):
    parent_bugzilla = bug_opened(bugs, broken_srpm)
    child_bugzilla = bug_opened(bugs, package)
    if parent_bugzilla and child_bugzilla:
        if child_bugzilla.id not in parent_bugzilla.blocks:
            bz_update = BZAPI.build_update(blocks_add=child_bugzilla.id)
            BZAPI.update_bugs([parent_bugzilla.id], bz_update)
            print(f"Bugzilla updated, {child_bugzilla.component} {child_bugzilla.id} now depends on {parent_bugzilla.component} {parent_bugzilla.id}")
        else:
            print(f"Bugzilla already blocked, {child_bugzilla.component} {child_bugzilla.id} depends on {parent_bugzilla.component} {parent_bugzilla.id}")

def print_dependency_tree():
    root = Node("/")

    for k, v in missing_dependencies.items():
        # insert keys as root children if they are not alredy in tree
        if len(findall_by_attr(root,k)) == 0:
            Node(k, parent=root)

        for child in v:
            # get parent
            existing_parent = findall_by_attr(root, k)
            # add child
            Node(child, parent=existing_parent[0])
            # get all childs with same name
            existing_child = findall_by_attr(root, child)
            # there never should be more than 2 of them
            if len(existing_child) > 1:
                try:
                    # assign new parent to the older child (one with whole dependency tree)
                    existing_child[0].parent=existing_parent[0]
                except LoopError as e:
                    print("Possible circular dependency.", file=sys.stderr)
                    print(str(e), file=sys.stderr)
                # remove the other duplicate child
                existing_child[1].parent=None

    for pre, _, node in RenderTree(root):
        if node.name in yellow_pkgs:
            p(f"{pre}{node.name}", fg="yellow")
        elif node.name in blue_pkgs:
            p(f"{pre}{node.name}", fg="blue")
        else:
            p(f"{pre}{node.name}", fg="green")


    most_common = Counter({k: len(v) for k, v in missing_dependencies.items()}).most_common(10)
    print("Top 10 of blockers (match_failed contains packages that could not be parsed):", file=sys.stderr)
    for pkg, count in most_common:
        print(pkg + ": " + str(count), file=sys.stderr)

async def failed_but_built(session, url, http_semaphore):
    """
    Sometimes, the package actually built, but is only marked as failed:
    https://pagure.io/copr/copr/issue/1209

    The build.log would be long, so we would attempt to open bugzillas.
    Here we get the index page of the results directory and we determine that:

     - failed builds only have 1 SRPM
     - succeeded builds have 1 SRPM and at least 1 built RPM
    """
    async with http_semaphore:
        logger.debug('failed_but_built %s', url)
        retry = False
        try:
            async with session.get(url) as response:
                text = await response.text()
                rpm_count = text.count(RPM_FILE)
                if rpm_count > 1:
                    with open('failed_but_built.lst', 'a') as f:
                        print(url, file=f)
                    return True
                return False
        except (aiohttp.client_exceptions.ClientConnectorError, aiohttp.client_exceptions.ServerDisconnectedError):
            await asyncio.sleep(1)
            retry = True
    if retry:
        return await failed_but_built(session, url, http_semaphore)


def index_link(package, build):
    return INDEX.format(package=package, build=build)


def buildlog_link(package, build):
    return index_link(package, build) + 'build.log.gz'


def rootlog_link(package, build):
    return index_link(package, build) + 'root.log.gz'


def builderlive_link(package, build):
    return index_link(package, build) + 'builder-live.log.gz'


class KojiError (Exception):
    pass


async def is_retired(package, command_semaphore):
    cmd = ('koji', 'list-pkgs', '--show-blocked',
           '--tag', TAG, '--package', package)
    async with command_semaphore:
        try:
            proc = await asyncio.create_subprocess_exec(*cmd,
                                                        stdout=asyncio.subprocess.PIPE)
        except Exception as e:
            raise KojiError(f'Failed to run koji: {e!r}') from None
        stdout, _ = await proc.communicate()
        return b'[BLOCKED]' in stdout


async def is_critpath(session, package, http_semaphore):
    try:
        json = await fetch(session, PDC.format(package=quote(package)), http_semaphore, json=True)
        for result in json['results']:
            if result['type'] == 'rpm':
                return result['critical_path']
        else:
            raise ValueError()
    except (aiohttp.ContentTypeError, ValueError):
        print(f'Could not check if {package} is \N{FIRE}', file=sys.stderr)
        return False


def bug(bugs, package):
    for b in bugs:
        if b.component == package:
            return b
    return None


def bug_opened(bugs, package):
    for b in bugs:
        if b.component == package and b.status != "CLOSED":
            return b
    return None


counter = Counter()

def pkgname(nevra):
    return nevra.rsplit("-", 2)[0]

def source_name(nevra):
    pkgs = repoquery(pkgname(nevra))
    for pkg in pkgs:  # a only gets evaluated here
    #    if pkg.reponame == "fedorarawhide":
        return pkg.source_name
    raise RuntimeError(f"Cannot find source for {pkgname(nevra)}. Hint: Remove the cache in {DNF_CACHEDIR}")

def rawhide_sack():
    """A DNF sack for rawhide, used for queries, cached"""
    base = dnf.Base()
    conf = base.conf
    conf.cachedir = DNF_CACHEDIR
    conf.substitutions['basearch'] = ARCH
    base.repos.add_new_repo('rawhide', conf,
        baseurl=['http://kojipkgs.fedoraproject.org/repos/rawhide/latest/$basearch/'],
        skip_if_unavailable=False,
        enabled=True)
    base.fill_sack(load_system_repo=False, load_available_repos=True)
    return base.sack

RAWHIDE_SACK = rawhide_sack()

def repoquery(name):
    return RAWHIDE_SACK.query().filter(name=name, latest=1).run()

def p(*args, **kwargs):
    if 'fg' in kwargs:
        counter[kwargs['fg']] += 1
    secho(*args, **kwargs)


async def process(
    session, bugs, package, build, status, http_semaphore, command_semaphore,
    *, browser_lock=None, with_reason=None, blues_file=None, magentas_file=None,
    greens_file=None
):
    if status != 'failed':
        return

    retired = await is_retired(package, command_semaphore)

    if retired:
        p(f'{package} is retired', fg='green')
        if greens_file:
            print(package, file=greens_file)
        return

    content_length, critpath = await gather_or_cancel(
        length(session, buildlog_link(package, build), http_semaphore),
        is_critpath(session, package, http_semaphore),
    )

    message = f'{package} failed len={content_length}'

    longlog = content_length > LIMIT

    if longlog and await is_blue(session, builderlive_link(package, build), http_semaphore):
        longlog = False

    repo_404 = False
    if await is_repo_404(session, builderlive_link(package, build), http_semaphore):
        longlog = True
        repo_404 = True

    if blues_file and not longlog:
        print(package, file=blues_file)

    bz = None
    if package in EXCLUDE:
        fg = 'cyan'
        message += f' (excluded: {EXCLUDE[package]})'
    elif repo_404:
        fg = 'magenta'
        message += ' (repo 404)'
        if magentas_file:
            print(package, file=magentas_file)
    else:
        bz = bug(bugs, package)
        if bz:
            message += f' bz{bz.id} {bz.status}'
            fg = 'yellow'

        if not bz or bz.status == "CLOSED":
            fg = 'red' if longlog else 'blue'
            if longlog:
                fg = 'red'
            else:
                fg = 'blue'
    if fg == 'yellow' or fg == 'blue':
        await guess_missing_dependency(session, package, build, http_semaphore,
                                      fg, bugs)

    if fg == 'red':
        if await is_timeout(session, builderlive_link(package, build), http_semaphore):
            message += ' (copr timeout)'
            fg = 'magenta'

    if critpath:
        message += ' \N{FIRE}'
    p(message, fg=fg)

    if (
        browser_lock
        and (not bz or bz.status == "CLOSED")
        and (longlog)
        and (str(package) not in EXCLUDE)
        and (fg != 'magenta')
    ):
        if not await failed_but_built(session, index_link(package, build), http_semaphore):
            reason = await guess_reason(session, builderlive_link(package, build), http_semaphore)
            if with_reason and not reason:
                return
            await open_bz(package, build, status, browser_lock, reason)


async def open_bz(package, build, status, browser_lock, reason=None):
    if reason == None:
        # General message for packages opened with --without-reason
        reason = {
            "long_description": "This report is automated and not very verbose, but we'll try to get back here with details.",
            "short_description": "",
        }
    summary = f"{package} fails to build with Python 3.13: {reason['short_description']}"

    description = dedent(f"""
        {package} fails to build with Python 3.13.0a3.

        {reason['long_description']}

        https://docs.python.org/3.13/whatsnew/3.13.html

        For the build logs, see:
        https://copr-be.cloud.fedoraproject.org/results/{COPR_STR}/fedora-rawhide-x86_64/{build:08}-{package}/

        For all our attempts to build {package} with Python 3.13, see:
        https://copr.fedorainfracloud.org/coprs/{COPR_STR_G}/package/{package}/

        Testing and mass rebuild of packages is happening in copr.
        You can follow these instructions to test locally in mock if your package builds with Python 3.13:
        https://copr.fedorainfracloud.org/coprs/{COPR_STR_G}/

        Let us know here if you have any questions.

        Python 3.13 is planned to be included in Fedora 41.
        To make that update smoother, we're building Fedora packages with all pre-releases of Python 3.13.
        A build failure prevents us from testing all dependent packages (transitive [Build]Requires),
        so if this package is required a lot, it's important for us to get it fixed soon.

        We'd appreciate help from the people who know this package best,
        but if you don't want to work on this now, let us know so we can try to work around it on our side.
    """)

    url_prefix = 'https://bugzilla.redhat.com/enter_bug.cgi?'
    params = {
        'short_desc': summary,
        'comment': description,
        'component': str(package),
        'blocked': TRACKER,
        'product': 'Fedora',
        'version': 'rawhide',
        #'bug_severity': 'high',
        'cc': 'mhroncok@redhat.com,ksurma@redhat.com'
    }

    # Rate-limit opening browser tabs
    async with browser_lock:
        webbrowser.open(url_prefix + urlencode(params))
        # open the build logs next to bz template, so it's easier to identify issues
        webbrowser.open(builderlive_link(package, build))
        await asyncio.sleep(1)


async def gather_or_cancel(*tasks):
    '''
    Like asyncio.gather, but if one task fails, others are cancelled
    '''
    tasks = [t if asyncio.isfuture(t) else asyncio.create_task(t) for t in tasks]
    try:
        return await asyncio.gather(*tasks)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

missing_dependencies = {
    'match_failed': []
}
yellow_pkgs = []
blue_pkgs = []

async def main(pkgs=None, open_bug_reports=False, with_reason=False, blues_file=None, magentas_file=None, greens_file=None, dependency_tree=None):
    logging.basicConfig(
        format='%(asctime)s %(name)s %(levelname)s: %(message)s',
        level=LOGLEVEL)

    http_semaphore = asyncio.Semaphore(20)
    command_semaphore = asyncio.Semaphore(10)

    # A lock to rate-limit opening browser tabs. If None, tabs aren't opened.
    if open_bug_reports:
        browser_lock = asyncio.Lock()
    else:
        browser_lock = None

    async with aiohttp.ClientSession(headers={"Connection": "close"}) as session:
        # we could stream the content, but meh, get it all, it's not that long
        packages = copr()
        bugs = bugzillas()
        packages, bugs = await asyncio.gather(packages, bugs)

        jobs = []

        for package in packages:
            try:
                package_name = package['builds']['latest']['source_package']['name']
                build = package['builds']['latest']['id']
                status = package['builds']['latest']['state']
                if pkgs and package_name not in pkgs:
                    continue
                await jobs.append(asyncio.ensure_future(process(
                    session, bugs, package_name, build, status,
                    http_semaphore, command_semaphore,
                    browser_lock=browser_lock, with_reason=with_reason,
                    blues_file=blues_file, magentas_file=magentas_file,
                    greens_file=greens_file
                )))
            except TypeError:
                pass
        try:
            await gather_or_cancel(*jobs)
        except KojiError as e:
            sys.exit(str(e))

        p(file=sys.stderr)
        for fg, count in counter.most_common():
            p(f'There are {count} {fg} lines ({EXPLANATION[fg]})',
              file=sys.stderr, fg=fg)

        if dependency_tree:
            print_dependency_tree()

@click.command()
@click.argument(
    'pkgs',
    nargs=-1,
)
@click.option(
    '--open-bug-reports/--no-open-bug-reports',
    help='Open a browser page (!) with a bug report template for each '
        + 'package that seems to need a bug report'
)
@click.option(
    '--with-reason/--without-reason',
    help='Use in combination with "--open-bug-reports",'
        + 'to open bug if reason was guessed'
)
@click.option(
    '--blues-file',
    type=click.File('w'),
    help='Dump blue-ish packages to a given file'
)
@click.option(
    '--magentas-file',
    type=click.File('w'),
    help='Dump magent-ish packages to a given file'
)
@click.option(
    '--greens-file',
    type=click.File('w'),
    help='Dump green-ish packages to a given file'
)
@click.option(
    '--dependency-tree/--no-dependency-tree',
    help='Show dependency tree of blue packages'
)
def run(pkgs, open_bug_reports, with_reason=None, blues_file=None, magentas_file=None, greens_file=None, dependency_tree=None):
    asyncio.run(main(pkgs, open_bug_reports, with_reason, blues_file, magentas_file, greens_file, dependency_tree))

if __name__ == '__main__':
    run()
