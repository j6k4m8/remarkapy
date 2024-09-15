"""
This module contains the logic to read the configuration file and return the values as a dictionary.
The file can be in multiple places, based upon the user's previously used SDKs.

For example, rmapi uses the following order to find the configuration file:

    1. ~/.rmapi
    2. $CONFIG_DIR/rmapi/.rmapi
    3. $CONFIG_DIR/rmapi/rmapi.conf

In any case, the configuration file is a simple key-value pair file, with keys,

    1. devicetoken
    2. usertoken

The values are the actual tokens that are used to authenticate the user with the reMarkable cloud.
In general, these start with `ey` in my experience (though this code does not check for that).

"""

import os
import pathlib
import pydantic


class RemarkapyConfig(pydantic.BaseModel):
    usertoken: str
    devicetoken: str


def get_config_or_raise(
    config_path_override: pathlib.Path | str | None = None, return_path: bool = False
) -> RemarkapyConfig | tuple[RemarkapyConfig, pathlib.Path]:
    """
    This function attempts to find the configuration file in the user's home directory, or in the
    $CONFIG_DIR directory. If the file is not found, it raises a FileNotFoundError.
    The XDG_CONFIG_HOME environment variable is used to determine the location of the configuration
    file based upon the rmapi SDK. On Mac, this is "~/Library/Application Support/rmapi".

    Arguments:
        config_path_override (pathlib.Path | str | None): The path to the configuration file, if it
            is not in one of the default locations.
        return_path (bool): If True, the function will return a tuple with the configuration and the
            path to the configuration file. If False, it will only return the configuration.

    Returns:
        RemarkapyConfig: A pydantic model with the usertoken and devicetoken.
        tuple[RemarkapyConfig, pathlib.Path]: If return_path is True, a tuple with the configuration
            and the path to the configuration file.

    Raises:
        FileNotFoundError: If the configuration file is not found.

    """
    if config_path_override is not None:
        config_path = pathlib.Path(config_path_override)

    else:
        options = [
            pathlib.Path.home() / ".rmapi",
            pathlib.Path(os.environ.get("RMAPI_CONFIG", "~")) / ".rmapi",
            pathlib.Path(os.environ.get("RMAPI_CONFIG", "~")) / ".rmapi.conf",
            pathlib.Path(os.environ.get("RMAPI_CONFIG", "~/.config"))
            / "rmapi"
            / ".rmapi",
            pathlib.Path(os.environ.get("RMAPI_CONFIG", "~/.config"))
            / "rmapi"
            / "rmapi.conf",
            pathlib.Path(os.environ.get("XDG_CONFIG_HOME", "~/.config"))
            / "rmapi"
            / ".rmapi",
            pathlib.Path(
                os.environ.get("XDG_CONFIG_HOME", "~/Library/Application Support")
            )
            / "rmapi"
            / ".rmapi",
            pathlib.Path(
                os.environ.get("XDG_CONFIG_HOME", "~/Library/Application Support")
            )
            / "rmapi"
            / "rmapi.conf",
        ]
        for option in options:
            option = pathlib.Path(option).expanduser().resolve()
            if option.exists():
                config_path = option
                break

        else:
            raise FileNotFoundError(
                "Configuration file not found. Tried the following locations: "
                + ", ".join([str(x) for x in options])
            )

    config = {}

    with open(config_path, "r") as f:
        for line in f:
            if line.strip().startswith("#"):
                continue
            line_parts = line.strip().split(":", 1)
            if len(line_parts) != 2:
                continue
            key, value = line_parts
            config[key.strip()] = value.strip()

    if return_path:
        return (
            RemarkapyConfig(
                usertoken=config["usertoken"], devicetoken=config["devicetoken"]
            ),
            config_path,
        )
    return RemarkapyConfig(
        usertoken=config["usertoken"], devicetoken=config["devicetoken"]
    )
