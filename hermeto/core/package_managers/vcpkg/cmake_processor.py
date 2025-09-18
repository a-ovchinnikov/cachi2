import json
import re
import reprlib
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Literal, Optional
from urllib.request import urlretrieve

import cmake_parser


def ensure_correct_command_was_fed(f):
    @wraps(f)
    def inner(*a, **k):
        # cmake scripts are case-insensitive, thus some ports decide to go with all caps.
        # Class names are derived from corresponding command names, but spelled in caps.
        if a[0].__name__.lower() != a[1].identifier.lower():
            raise ValueError(
                f"Wrong input command indentifier. Want '{a[0].__name__.lower()}', got "
                f"{a[1].identifier.lower()}"
            )
        return f(*a, **k)
    return inner


def _parse_str(string):
    return list(cmake_parser.parser.parse_raw(string))[0]


# A simple storage to help me with not forgetting to add command implementations
class Memo:
    def __init__(self):
        # To make this least appealing for modification
        self.registry = tuple()

    def register_implementation(self, f):
        self.registry = self.registry + (f,)
        def w(f):
            return f
        return w(f)

reg = Memo()


def dependency_name(raw_dep):
    try:
        return raw_dep["name"]
    except TypeError:
        return raw_dep


path_to_ports = Path(os.environ['HERMETO_VCPKG_PATH_TO_PORTS'])


def find_deps(port_path, root=True, seen=None):
    if seen is None:
        seen = set()
    port_data = json.loads((Path(port_path)/"vcpkg.json").read_text())
    # icu depends on itself and creates a loop.
    direct_deps = [dn for d in port_data.get("dependencies", [])
                   if (dn:=dependency_name(d)) != Path(port_path).name and dn not in seen]
    feature_deps = [dn for (_, f) in port_data.get("features", {}).items()
                    for d in f.get("dependencies", [])
                    if (dn:=dependency_name(d)) != Path(port_path).name and dn not in seen]
    seen.update(direct_deps + feature_deps)
    other_deps = sum([find_deps(path_to_ports/d, root=False, seen=seen)
                      for d in (direct_deps + feature_deps)], [])
    if root:
        return set(direct_deps + feature_deps + other_deps)
    return (direct_deps + feature_deps + other_deps)


def first_innermost_variable(strn):
    """Searches for ${variable} in str, returns name in curly brackets.

    Variables could be nested.
    >>> first_innermost_variable("${foobar}")
    'foobar'
    >>> first_innermost_variable("${foo${baz}bar}")
    'baz'
    >>> first_innermost_variable("${foo${quux}${baz}bar}")
    'quux'
    >>> first_innermost_variable("${foo${qu${meep}ux}${baz}bar}")
    'meep'
    """
    out = []
    lst = list(strn)
    while lst:
        s = lst.pop(0)
        if s == '$' and lst and lst[0] == '{':
            lst.pop(0)
            out.clear()
        elif s == '}':
            return "".join(out)
        else:
            out.append(s)
    raise ValueError("Unbalanced string")


def cbrackets_are_balanced_in(strn):
    """
    >>> cbrackets_are_balanced_in("${}")
    True
    >>> cbrackets_are_balanced_in("${}}")
    False
    >>> cbrackets_are_balanced_in("${}{")
    False

    Note that the sequence below returns True: this function checks
    just that the number of cbrackets is correct, not the ordering
    >>> cbrackets_are_balanced_in("${}}${")
    True
    >>> cbrackets_are_balanced_in("${}${}")
    True
    """
    lcbraket_count = strn.count("{")
    rcbraket_count = strn.count("}")
    if lcbraket_count != rcbraket_count:
        return False
    return True


def scbrackets_sequence_is_correct_in(strn):
    """A universal checker

    A string is well terminated when there are enough } to match all ${s.
    Stray {s are ignored, stray }s are ignored too.
    >>> scbrackets_sequence_is_correct_in("${foo}")
    True

    This one is True because
    >>> scbrackets_sequence_is_correct_in("${foo}}")
    True
    >>> scbrackets_sequence_is_correct_in("${foo}{")
    True
    >>> scbrackets_sequence_is_correct_in("${foo}${")
    False
    >>> scbrackets_sequence_is_correct_in("${foo}${}")
    True
    >>> scbrackets_sequence_is_correct_in("${foo}${")
    False
    >>> scbrackets_sequence_is_correct_in("${foo}${}}")
    True
    >>> scbrackets_sequence_is_correct_in("${foo}${bar}")
    True
    >>> scbrackets_sequence_is_correct_in("${fo${quuxo}${bar}")
    False
    >>> scbrackets_sequence_is_correct_in("${fo${quux}o}${bar}")
    True
    """
    balance = 0
    for pos, sym in enumerate(strn):
        if sym == "$" and pos+1<=len(strn) and strn[pos+1] == "{":
            balance += 1
        if sym == "}" and balance:  # i.e. we've seen at least one ${
            balance -= 1
        if balance<0:
            return False
    return balance == 0

def contains_variables(strn):
    """
    >>> contains_variables("foobar")
    False
    >>> contains_variables("${foobar")
    False
    >>> contains_variables("${foobar}")
    True
    >>> contains_variables("}$foobar}")
    False
    """
    # TODO: should it be just the presence of ${ and }?
    return "${" in strn and "}" in strn and scbrackets_sequence_is_correct_in(strn)


ReifyGuard = object()

def substitute(what, to_what, in_what):
    if to_what is ReifyGuard:
        return in_what
    return re.sub("\\$\\{" + what + "\\}", to_what, in_what, count=1)


@dataclass
class Value:
    """A dataclass to hold a value of an argument.

    Can be either a plain string or could contain a variable to be substituted by Cmake.
    """

    contents: str

    def reify(self, context=None):
        if context is None:
            if contains_variables(self.contents):
                return self
            else:
                return self.contents
        if "${" not in self.contents:
            return self.contents
        to_reify = self.contents
        while "${" in to_reify:
            to_substitute = first_innermost_variable(to_reify)
            to_reify_old = to_reify
            to_reify = substitute(to_substitute, context.get(to_substitute, ReifyGuard), to_reify)
            if to_reify is to_reify_old:
                # we are running in circles, there is no mathcing substitution
                return self.__class__(contents=to_reify)
        return to_reify

    @property
    def needs_reification(self):
        return contains_variables(self.contents)


class BaseCmakeCommand(ABC):
    @property
    def needs_reification(self):
        return not all(isinstance(x, (str, list, type(None))) or not x.needs_reification
                       for x in self.__dict__.values())

    def reify(self, context):
        """Fields can contain values that must be expanded within an environment (aka context).
        """
        source = dict()
        for k, v in self.__dict__.items():
            source[k] = v.reify(context) if isinstance(v, Value) else v
        return self.__class__(**source)

    def __repr__(self):
        ar = reprlib.Repr()
        ar.maxstring = 20
        args = ", ".join([f"{k}={ar.repr(v)}" for k, v in self.__dict__.items()
                          if (v is not None) and (k != "OUT_SOURCE_PATH")])
        return f"{self.__class__.__name__}({args})"

    @abstractmethod
    def from_command(cls, a_command):
        """A classmethod to process a command as returned by cmake parser."""

    @abstractmethod
    def do_special_magic(self):
        """Actual implementation of a command."""


class BaseGitForge(BaseCmakeCommand):
    """Processing of commnad for most of the forges is very similar."""

    @classmethod
    @ensure_correct_command_was_fed
    def from_command(cls, a_command):
        args = a_command.args[:]
        initializer = {}
        while args:
            arg = args.pop(0)
            if arg.value in cls.__dataclass_fields__.keys():
                if not args or args[0].value in cls.__dataclass_fields__.keys():
                    # NOTE: this is a crude hack around baresip-libre
                    # which defines 'PATCHES' keyword, but then provides no
                    # patches; libadwaita does the same.
                    if arg.value == "PATCHES":
                        pass
                    else:
                        raise ValueError(f"Missing value for {arg}")
                if arg.value != "PATCHES":
                    initializer[arg.value] = Value(contents=args.pop(0).value).reify()
                else:
                    initializer[arg.value] = []
                    while args and args[0].value not in cls.__dataclass_fields__.keys():
                        initializer[arg.value].append(Value(contents=args.pop(0).value).reify())
            else:
                pass
        return cls(**initializer)


# TODO: process return variables. OUT_SOURCE_PATH is set and is very rarely used
@reg.register_implementation
@dataclass
class VCPKG_FROM_GITHUB(BaseGitForge):
    # This one will likely always be equal to SOURCE_PATH which is set by cmake and points
    # to a directory where Cmakelist.txt resides. We can safe-ishly ignore it for now.
    OUT_SOURCE_PATH: Value | str  # making this a union for now since I would want to reify it asap
    REPO: Value | str
    REF: Value | str
    SHA512: Value | str
    HEAD_REF: Optional[Value | str] = None
    GITHUB_HOST: Optional[Value | str] = None
    AUTHORIZATION_TOKEN: Optional[Value | str] = None
    FILE_DISAMBIGUATOR: Optional[Value | str] = None
    PATCHES: Optional[list[str]] = None

    def do_special_magic(self, path=Path("/tmp/foo"), environemnt=None):
        path.mkdir(parents=True, exist_ok=True)
        # The filename mimics filenames observed in vcpkg/downloads
        # Some ports (boinc) contain '/' in file names which get substituted by '_'
        # at some point.
        if '/' in self.REF:
            self.REF = self.REF.replace("/", "_")
        filename = path / ("-".join(self.REPO.split("/")) + "-" + self.REF + ".tar.gz")
        url = f"https://github.com/{self.REPO}/archive/{self.REF}.tar.gz"
        if contains_variables(url):
            print(f"Warning! {url} contains unreified variables!")
            raise ValueError("Failed to fully reify")
        else:
            urlretrieve(url, filename)
            return True


# example: at-spi2-atk
@reg.register_implementation
@dataclass
class VCPKG_FROM_GITLAB(BaseGitForge):
    OUT_SOURCE_PATH: Value | str  # making this a union for now since I would want to reify it asap
    REPO: Value | str
    REF: Value | str
    SHA512: Value | str
    HEAD_REF: Optional[Value | str] = None
    GITLAB_URL: Optional[Value | str] = None  # TODO: check if this is actually optional
    AUTHORIZATION_TOKEN: Optional[Value | str] = None
    FILE_DISAMBIGUATOR: Optional[Value | str] = None
    PATCHES: Optional[list[str]] = None

    def do_special_magic(self, path=Path("/tmp/foo"), environemnt=None):
        return False


# example: blaze
@reg.register_implementation
@dataclass
class VCPKG_FROM_BITBUCKET(BaseGitForge):
    OUT_SOURCE_PATH: Value | str  # making this a union for now since I would want to reify it asap
    REPO: Value | str
    REF: Value | str
    SHA512: Value | str
    HEAD_REF: Optional[Value | str] = None
    PATCHES: Optional[list[str]] = None

    def do_special_magic(self, path=Path("/tmp/foo"), environemnt=None):
        return False


# example dbghelp
@reg.register_implementation
@dataclass
class VCPKG_GET_WINDOWS_SDK(BaseCmakeCommand):
    # A stub to deal with windows-only packages
    WINDOWS_SDK: Optional[Value | str] = None  # this is a shameless plug for an outvar

    @classmethod
    @ensure_correct_command_was_fed
    def from_command(cls, a_command):
        args = a_command.args[:]
        initializer = {}
        while args:
            arg = args.pop(0)
        return cls(**initializer)

    def reify(self, context):
        return self

    def do_special_magic(self, path=Path("/tmp/foo"), environemnt=None):
        return False


# example dbghelp
@reg.register_implementation
@dataclass
class IGNITION_MODULAR_LIBRARY(BaseCmakeCommand):
    # A stub to deal with ignition packages packages

    @classmethod
    @ensure_correct_command_was_fed
    def from_command(cls, a_command):
        args = a_command.args[:]
        initializer = {}
        while args:
            arg = args.pop(0)
        return cls(**initializer)

    def reify(self, context):
        return self

    def do_special_magic(self, path=Path("/tmp/foo"), environemnt=None):
        return False


@reg.register_implementation
@dataclass
class QT_INSTALL_SUBMODULE:
    # A stub to deal with qt

    @classmethod
    @ensure_correct_command_was_fed
    def from_command(cls, a_command):
        args = a_command.args[:]
        initializer = {}
        while args:
            arg = args.pop(0)
        return cls(**initializer)

    def reify(self, context):
        return self

    def do_special_magic(self, path=Path("/tmp/foo"), environemnt=None):
        return False


@reg.register_implementation
@dataclass
class QT_SUBMODULE_INSTALLATION(BaseCmakeCommand):
    # A stub to deal with qt

    @classmethod
    @ensure_correct_command_was_fed
    def from_command(cls, a_command):
        args = a_command.args[:]
        initializer = {}
        while args:
            arg = args.pop(0)
        return cls(**initializer)

    def reify(self, context):
        return self

    def do_special_magic(self, path=Path("/tmp/foo"), environemnt=None):
        return False


@reg.register_implementation
@dataclass
class VCPKG_DOWNLOAD_DISTFILE(BaseCmakeCommand):
    ARCHIVE: None
    URLS: Value | str
    FILENAME: Value | str
    SHA512: Value | str

    @classmethod
    @ensure_correct_command_was_fed
    def from_command(cls, a_command):
        args = a_command.args[:]
        initializer = {'ARCHIVE': None}
        while args:
            arg = args.pop(0)
            if arg.value in cls.__dataclass_fields__.keys():
                # ARCHIVE is not supposed to be set
                if not args or (args[0].value in cls.__dataclass_fields__.keys() and arg.value != 'ARCHIVE'):
                    raise ValueError(f"Missing value for {arg}")
                if arg.value == 'ARCHIVE':
                    continue
                if arg.value != "URLS":
                    initializer[arg.value] = Value(contents=args.pop(0).value).reify()
                else:
                    initializer[arg.value] = []
                    while args and args[0].value not in cls.__dataclass_fields__.keys():
                        initializer[arg.value].append(Value(contents=args.pop(0).value).reify())
            else:
                pass
        return cls(**initializer)

    def reify(self, context):
        source = dict()
        for k, v in self.__dict__.items():
            if isinstance(v, list):
                source[k] = []
                for el in v:
                    if isinstance(el, Value):
                        source[k].append(el.reify(context))
                    else:
                        source[k].append(el)
            else:
                source[k] = v.reify(context) if isinstance(v, Value) else v
        return self.__class__(**source)

    def do_special_magic(self, path=Path("/tmp/foo"), environemnt=None):
        path.mkdir(parents=True, exist_ok=True)
        if '/' in self.FILENAME:
            self.FILENAME = self.FILENAME.replace("/", "_")  # this is a dirty hack from boinc
        for url in self.URLS:
            if (isinstance(url, Value) and url.needs_reification) or (isinstance(self.FILENAME, Value) and self.FILENAME.needs_reification):
                raise ValueError(f"Something was not reified properly: {url=}; {self.FILENAME=}")

        return False


@reg.register_implementation
@dataclass
class VCPKG_FROM_GIT(BaseGitForge):
    # This one will likely always be equal to SOURCE_PATH which is set by cmake and points
    # to a directory where Cmakelist.txt resides. We can safe-ishly ignore it for now.
    OUT_SOURCE_PATH: Value | str  # making this a union for now since I would want to reify it asap
    URL: Value | str
    REF: Value | str
    FETCH_REF: Optional[Value | str] = None
    HEAD_REF: Optional[Value | str] = None
    TAG: Optional[Value | str] = None
    LFS: Optional[Value | str] = None
    PATCHES: Optional[list[str]] = None

    def do_special_magic(self, path=Path("/tmp/foo"), environemnt=None):
        # What it does under the hood:
        #   COMMAND "${GIT}" fetch "${arg_URL}" "${ref_to_fetch}" ${git_fetch_shallow_param} -n
        # git_fetch_shallow_param is set when FETCH_REF is set, FETCH_REF is set in just three
        # recipes -- or in more. It is safe-ish to assume that it is always set to
        # "--depth 1" and fix in other cases
        path.mkdir(parents=True, exist_ok=True)
        # TODO: must run git init in a dir that is about to be populated
        to_run = f"git fetch {self.URL} {self.REF} --depth 1"
        # TODO: after the run:
        # if HEAD_REF is defined:
        # string(REPLACE "/" "_-" sanitized_ref "${arg_HEAD_REF}")
        # else:
        # string(REPLACE "/" "_-" sanitized_ref "${arg_REF}")
        # set(temp_archive "${DOWNLOADS}/temp/${PORT}-${sanitized_ref}.tar.gz")
        #   COMMAND "${GIT}" rev-parse "${expected_rev_parse}" OUTPUT_VARIABLE rev_parse_ref
        #   COMMAND "${GIT}" -c core.autocrlf=false archive "${rev_parse_ref}" -o "${temp_archive}"
        if contains_variables(self.URL):
            print(f"Warning! {self.URL} contains unreified variables!")
            raise ValueError("Failed to fully reify")
        else:
            return False


# example: argtable2
@reg.register_implementation
@dataclass
class VCPKG_FROM_SOURCEFORGE(BaseGitForge):
    # This one will likely always be equal to SOURCE_PATH which is set by cmake and points
    # to a directory where Cmakelist.txt resides. We can safe-ishly ignore it for now.
    OUT_SOURCE_PATH: Value | str  # making this a union for now since I would want to reify it asap
    REPO: Value | str
    REF: Optional[Value | str] = None  # looks like it can be undefined
    SHA512: Optional[Value | str] = None
    FILENAME: Optional[Value | str] = None
    WORKING_DIRECTORY: Optional[Value | str] = None
    PATCHES: Optional[list[str]] = None

    def do_special_magic(self, path=Path("/tmp/foo"), environemnt=None):
        # NOTE: this defines a ton of mirrors for SF:
        # set(all_urls "${url}/download")
        # foreach(mirror IN LISTS sourceforge_mirrors)
        #     list(APPEND all_urls "${url}/download?use_mirror=${mirror}")
        # endforeach()
        # What it does under the hood:
        # set(sourceforge_host "https://sourceforge.net/projects")
        # if(DEFINED arg_REF)
        #     set(url "${sourceforge_host}/${org_name}/files/${repo_name}/${arg_REF}/${arg_FILENAME}")
        # elseif(DEFINED repo_name)
        #     set(url "${sourceforge_host}/${org_name}/${repo_name}/files/${arg_FILENAME}")
        # else()
        #     set(url "${sourceforge_host}/${org_name}/files/${arg_FILENAME}")
        # endif()
        path.mkdir(parents=True, exist_ok=True)
        sf_url = "https://sourceforge.net/projects"
        if "/" in self.REPO:
            org_name, repo_name = self.REPO.split("/")
        else:
            org_name, repo_name = self.REPO, ""
        if self.REF is not None:
            url = f"{sf_url}/{org_name}/files/{repo_name}/{self.REF}/{self.FILENAME}"
        elif repo_name:
            url = f"{sf_url}/{org_name}/{repo_name}/files/{self.FILENAME}"
        else:
            url = f"{sf_url}/{org_name}/files/{self.FILENAME}"

        return False


@reg.register_implementation
@dataclass
class SET:
    """Straightforward-ish environment mutator."""

    What: Value | str
    ToWhat: Value | str

    def do_special_magic(self, environemnt):
        to_what = self.ToWhat.reify(environemnt)
        if isinstance(to_what, str):
            environemnt[self.What.contents] = to_what

    @classmethod
    @ensure_correct_command_was_fed
    def from_command(cls, a_command):
        args = a_command.args[:]
        # Generally set allows to assign a name to a list, however this is not really
        # useful to Hermeto's case, thus nothing is done about it. An example of
        # multiple assignment is angle.
        return cls(What=Value(contents=args[0].value), ToWhat=Value(contents=args[1].value))

    def reify(self, *a, **k):
        return self


@reg.register_implementation
@dataclass
class STRING:
    r"""Processes a string and modifies environment basing on results.

    String "function" in cmake is rather versatile, it accepts multiple keywords which
    select specific string operation. Furthermore, as all cmake "functions" it does not
    return a value, setting a variable in a shared environment instead. The class as it is now
    is not very wieldy and should be eventually replaced by more specific classes
    for each individual command.

    Note, that not all string operations are currently handled. The oeprations were added
    on "as needed" basis meaning that only those operations used anywhere in the ports during
    preparations to sources download were added. Others are missing since this is not
    a proper re-implementation of cmake.

    Various ports use slightly different approaches to extracting data from strings with regexes.
    What follows are several examples taken from different ports which highlight the most frequent
    aspects of cmake regexps.

    The example below is taken from glibmm:
    >>> inpt = 'string(REGEX MATCH "^([0-9]*[.][0-9]*)" GLIBMM_MAJOR_MINOR "${VERSION}")'
    >>> STRING.from_command(_parse_str(inpt))  # doctest: +NORMALIZE_WHITESPACE
    STRING(cmd='REGEX', What='^([0-9]*[.][0-9]*)', WithWhat=None,
           ToWhat='GLIBMM_MAJOR_MINOR', InWhat=Value(contents='${VERSION}'), subcmd='MATCH')

    The example below is taken from libraqm. Note multiple groups within a re and escapes
    for literal dots:
    >>> inpt = r'string(REGEX MATCH "([0-9]+)\\.([0-9]+)\\.([0-9]+)" RAQM_VERSION "${VERSION}")'
    >>> s = STRING.from_command(_parse_str(inpt))
    >>> s  # doctest: +NORMALIZE_WHITESPACE
    STRING(cmd='REGEX', What='([0-9]+)\\\\.([0-9]+)\\\\.([0-9]+)', WithWhat=None,
           ToWhat='RAQM_VERSION', InWhat=Value(contents='${VERSION}'), subcmd='MATCH')

    The port script relies on implicit variables which are added to the environment
    during regex processing. These variables could be set when STRING command is executed.
    >>> env = {"VERSION": "1.0.42"}
    >>> s.reify(env).do_special_magic(env)
    >>> env  # doctest: +NORMALIZE_WHITESPACE
    {'VERSION': '1.0.42',
     'CMAKE_MATCH_1': '1', 'CMAKE_MATCH_2': '0', 'CMAKE_MATCH_3': '42',
     'RAQM_VERSION': '1.0.42'}

    A snippet below is taken from x264. Note, that the match is supposed to
    happen at the end of string and the lack of grouping which results in not
    setting of any of implied variables.
    >>> inpt = r'string(REGEX MATCH "[0-9]+\$" revision "${VERSION}")'
    >>> s = STRING.from_command(_parse_str(inpt))
    >>> s  # doctest: +NORMALIZE_WHITESPACE
    STRING(cmd='REGEX', What='[0-9]+\\$', WithWhat=None,
           ToWhat='revision', InWhat=Value(contents='${VERSION}'), subcmd='MATCH')
    >>> env = {"VERSION": "1.0.42"}
    >>> s.reify(env).do_special_magic(env)
    >>> env
    {'VERSION': '1.0.42', 'revision': '42'}

    The example below is taken from boost-cmake.
    >>> inpt = r'string(REGEX MATCH "([0-9]+)\\.([0-9]+)\\.([0-9]+)" SEMVER_VERSION "${VERSION}")'
    >>> s = STRING.from_command(_parse_str(inpt))
    >>> s  # doctest: +NORMALIZE_WHITESPACE
    STRING(cmd='REGEX', What='([0-9]+)\\\\.([0-9]+)\\\\.([0-9]+)', WithWhat=None,
           ToWhat='SEMVER_VERSION', InWhat=Value(contents='${VERSION}'), subcmd='MATCH')
    >>> env = {"VERSION": "1.0.42"}
    >>> s.reify(env).do_special_magic(env)
    >>> env  # doctest: +NORMALIZE_WHITESPACE
    {'VERSION': '1.0.42',
     'CMAKE_MATCH_1': '1', 'CMAKE_MATCH_2': '0', 'CMAKE_MATCH_3': '42',
     'SEMVER_VERSION': '1.0.42'}

    The example below is taken from appstream-glib.
    >>> inpt = 'string(REPLACE "." "_" appstream_glib_version "appstream_glib_${VERSION}")'
    >>> s = STRING.from_command(_parse_str(inpt))
    >>> s  # doctest: +NORMALIZE_WHITESPACE
    STRING(cmd='REPLACE', What='.', WithWhat='_', ToWhat='appstream_glib_version',
           InWhat=Value(contents='appstream_glib_${VERSION}'), subcmd=None)
    >>> env = {"VERSION": "1.0.42"}
    >>> s.reify(env).do_special_magic(env)
    >>> env  # doctest: +NORMALIZE_WHITESPACE
    {'VERSION': '1.0.42', 'appstream_glib_version': 'appstream_glib_1_0_42'}

    The example below is taken from boinc. Note the use of group numbers.
    >>> inpt = 'string(REGEX REPLACE "^([0-9]*[.][0-9]*)[.].*" "\\1" MAJOR_MINOR "${VERSION}")'
    >>> s = STRING.from_command(_parse_str(inpt))
    >>> s  # doctest: +NORMALIZE_WHITESPACE
    STRING(cmd='REGEX', What='^([0-9]*[.][0-9]*)[.].*', WithWhat='\\1',
           ToWhat='MAJOR_MINOR', InWhat=Value(contents='${VERSION}'), subcmd='REPLACE')
    >>> env = {"VERSION": "1.0.42"}
    >>> s.reify(env).do_special_magic(env)
    >>> env  # doctest: +NORMALIZE_WHITESPACE
    {'VERSION': '1.0.42', 'MAJOR_MINOR': '1.0'}

    The following example is adapted from libgxps
    >>> inpt = 'string(SUBSTRING ${VERSION} 0 3 MAJOR_MINOR)'
    >>> s = STRING.from_command(_parse_str(inpt))
    >>> s  # doctest: +NORMALIZE_WHITESPACE
    STRING(cmd='SUBSTRING', What='0', WithWhat='3', ToWhat='MAJOR_MINOR',
           InWhat=Value(contents='${VERSION}'), subcmd=None)
    >>> env = {"VERSION": "1.0.42"}
    >>> s.reify(env).do_special_magic(env)
    >>> env  # doctest: +NORMALIZE_WHITESPACE
    {'VERSION': '1.0.42', 'MAJOR_MINOR': '1.0'}
    """

    cmd: Literal["REPLACE", "REGEX"]
    What: str  # Depending on (command, subcommand) will hold some pattern, TODO: rename to pattern
    WithWhat: str  # Optional (TODO) replacement. substitution?
    ToWhat: str   # effectively the return value: in this variable we'll store the result in an env
    InWhat: Value | str   # input to process
    subcmd: Optional[Literal["REPLACE"]] = None  # only present if it is a regex

    def do_special_magic(self, environemnt):
        # note, that reification should have happpened by now -- this must be designed better
        if self.cmd == "REPLACE":
            environemnt[self.ToWhat] = self.InWhat.replace(self.What, self.WithWhat)
        elif self.cmd == "SUBSTRING":
            environemnt[self.ToWhat] = self.InWhat[int(self.What):int(self.WithWhat)]
        elif self.cmd == "REGEX" and self.subcmd == "REPLACE":
            # cmake uses special group syntax which has to be converted to Python regexp.
            self.WithWhat = re.sub(r'\\\\(\d+)', r'\\g<\g<1>>', self.WithWhat)
            environemnt[self.ToWhat] = re.sub(self.What, self.WithWhat, self.InWhat)
        elif self.cmd == "REGEX" and self.subcmd == "MATCH":
            match = re.search(self.What.replace("\\", ""), self.InWhat)

            if match is not None:
                for group_num, group_val in enumerate(match.groups(), start=1):
                    environemnt[f"CMAKE_MATCH_{group_num}"] = group_val
                environemnt[self.ToWhat] = match.group()  # just one group
                # NOTE: the whole match goes into CMAKE_MATCH_0, however it does not seem to be
                #       used anywhere in the standard repo
            else:
                raise ValueError("Broken regexp detected")
        else:
            raise ValueError(f"Unsupported (cmd, subcomd): ({self.cmd}, {self.subcmd})")

    @classmethod
    @ensure_correct_command_was_fed
    def from_command(cls, a_command):
        args = a_command.args[:]
        if len(args) == 5:
            cmd, subcmd =  args[0].value, args[1].value
            if cmd == 'SUBSTRING':
                return cls(cmd=args[0].value, subcmd=None,
                           What=args[2].value,  # this is always a str
                           ToWhat=args[4].value,  # out var
                           WithWhat=args[3].value,
                           InWhat=Value(contents=args[1].value))
            if cmd == "REPLACE":
                return cls(cmd=args[0].value, subcmd=None,
                           What=args[1].value,  # this is always a str
                           WithWhat=args[2].value,  # substitution, this is always a str
                           ToWhat=args[3].value,  # out var
                           InWhat=Value(contents=args[4].value))  # input var
            if subcmd == "MATCH":
                return cls(cmd=args[0].value, subcmd=subcmd,
                           What=args[2].value,  # regexp, always a str
                           ToWhat=args[3].value,  # out var
                           WithWhat=None,
                           InWhat=Value(contents=args[4].value))
            return cls(cmd=args[0].value, subcmd=None,
                       What=args[1].value,  # this is always a str
                       WithWhat=args[2].value,  # this is always a str
                       ToWhat=args[3].value,  # this is always a str
                       InWhat=Value(contents=args[4].value))
        elif len(args) == 6:
            subcmd = args[1].value
            if subcmd == "REPLACE":
                return cls(cmd=args[0].value, subcmd=subcmd,
                           What=args[2].value,  # regexp
                           WithWhat=args[3].value,  # substitution
                           ToWhat=args[4].value,  # out var
                           InWhat=Value(contents=args[5].value))  # input var
            else:
                raise ValueError(f"Unknown string subcommand: {subcmd}")
        else:
            # A visible fall-back, should not be reachable in practice, could end up being
            # reachable due to peculiarities of experimental processing.
            return cls(cmd=args[0].value, subcmd="MISSING",
                       What="IGNORED",
                       ToWhat="IGNORED",
                       WithWhat=None,
                       InWhat=Value(contents="IGNORED"))

    def reify(self, context=None):
        return self.__class__(
            cmd=self.cmd, subcmd=self.subcmd, What=self.What, WithWhat=self.WithWhat,
            ToWhat=self.ToWhat, InWhat=self.InWhat.reify(context=context)
        )


def get_parsed_portfile(portname):
    port_text = (path_to_ports / portname / "portfile.cmake").read_text()
    # Parsing raw since some commands end up being hidden within if_true or if_false branches
    # of 'if' command. Since branching could happen during runtime basing on vcpkg runtime
    # state the most robust way is to predownload all possible artifacts and then let vcpkg
    # decide which are needed during build time. This requires me to ignore if branches.
    return list(cmake_parser.parser.parse_raw(port_text))


def get_port_json(portname):
    return json.loads((path_to_ports / portname / "vcpkg.json").read_text())


def any_key_that_is_present(dct, keys):
    for key in keys:
        if key in dct:
            return dct[key]
    return "THIS-IS-NOT-A-VERSION!"


def prepopulate_environment_from_port_json(portname):
    data = get_port_json(portname)
    # version-date is used in breakpad
    return {
        "VERSION": any_key_that_is_present(data, ("version", "version-string", "version-semver", "version-date")),
        # some ports need these variables:
        "PORT": portname,  # apparently set by vcpkg, some ports rely on it
        "CURRENT_PORT_DIR": str(path_to_ports / portname),
        "CURRENT_BUILDTREES_DIR": str(path_to_ports.parent / "buildtrees"),
    }


downloaders = (
    # core ones:
    "vcpkg_from_bitbucket", "vcpkg_from_github", "vcpkg_from_git",
    "vcpkg_from_gitlab", "vcpkg_from_sourceforge", "vcpkg_download_distfile",
    # dumb helpers:
    "vcpkg_get_windows_sdk", "ignition_modular_library",
)


# TODO: a better heuristics: work back from all the downloaders and
#       process only those commands which modify variables used by the downloaders.
def prune_commands_list(commands_list):
    # find position of the latest download command
    pos = len(commands_list) - 1
    found_downloader = False
    while pos + 1:
        if hasattr(commands_list[pos], 'identifier') and commands_list[pos].identifier.lower() in downloaders:
            found_downloader = True
            break
        pos -= 1
    if found_downloader:
        return commands_list[:pos + 1]
    return commands_list


def decadent_convert_to_inner(port_parse_list):
    out = []
    for parse_element in prune_commands_list(port_parse_list):
        for cls in reg.registry:
            try:
                res = cls.from_command(parse_element)
                if res is None:
                    print("caught a None:", parse_element)
                    if (parse_element.identifier == 'string'
                            and parse_element.args[0].value == 'APPEND'):
                        continue
                out.append(res)
            except Exception:
                pass
    return out


def needs_reification(port_result):
    return any(x.needs_reification for x in port_result)


def reify_single_port(portname):
    available_commands = decadent_convert_to_inner(get_parsed_portfile(portname))
    environemnt = prepopulate_environment_from_port_json(portname)
    out = []
    for ac in available_commands:
        val = ac.reify(context=environemnt)
        try:
            res = val.do_special_magic(environemnt=environemnt)
        except re.PatternError:
            raise
        if res:
            out = True
    return out, environemnt
