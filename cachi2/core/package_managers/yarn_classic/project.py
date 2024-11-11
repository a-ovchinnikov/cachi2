"""
Parse the relevant files of a yarn project.

It also provides basic utility functions. The main logic to resolve and prefetch
the dependencies should be implemented in other modules.
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Literal, Union

from cachi2.core.errors import PackageRejected
from cachi2.core.rooted_path import RootedPath

log = logging.getLogger(name=__name__)

ConfigKind = Literal["package_json", "yarnlock"]


@dataclass
class _CommonConfigFile(ABC):
    """A base class for representing a config file.

    :param path: the path to the config file, relative to the request source dir
    :param data: the raw data for the config file content
    """

    _path: RootedPath
    _data: dict[str, Any]

    @property
    def data(self) -> dict[str, Any]:
        return self._data

    @property
    def path(self) -> RootedPath:
        return self._path

    @property
    @abstractmethod
    def config_kind(self) -> ConfigKind:
        """Return kind of ConfigFile instance."""

    @classmethod
    @abstractmethod
    def from_file(cls, path: RootedPath) -> "_CommonConfigFile":
        """Construct a ConfigFile instance."""


class PackageJson(_CommonConfigFile):
    """A package.json file.

    This class abstracts the underlying attributes and only exposes what
    is relevant for the request processing.
    """

    @property
    def config_kind(self) -> ConfigKind:
        """Return kind of this ConfigFile."""
        return "package_json"

    @property
    def install_config(self) -> dict[str, Any]:
        """Get the installConfig dict."""
        return self.data.get("installConfig", {})

    @classmethod
    def from_file(cls, path: RootedPath) -> "PackageJson":
        """Construct a PackageJson instance."""
        try:
            package_json_data = json.loads(path.path.read_text())
        except FileNotFoundError:
            raise PackageRejected(
                reason="The package.json file must be present for the yarn package manager",
                solution=(
                    "Please double-check that you have specified the correct path "
                    "to the package directory containing this file"
                ),
            )
        except json.decoder.JSONDecodeError as e:
            raise PackageRejected(
                reason=f"Can't parse the {path.subpath_from_root} file. {e}",
                solution=(
                    "The package.json file must contain valid JSON. "
                    "Refer to the parser error and fix the contents of the file."
                ),
            )

        return cls(path, package_json_data)


ConfigFile = Union[PackageJson]