"""
This module contains the logic for main reMarkable API.

The API calls themselves are handled by the Client class.
"""

import logging
import pathlib

import httpx

from .configfile import RemarkapyConfig, get_config_or_raise

logger = logging.getLogger(__name__)


class RemarkableAPIError(Exception): ...


class URLS:
    # https://github.com/juruen/rmapi/blob/master/config/url.go
    AUTH_HOST = "https://webapp-prod.cloud.remarkable.engineering"
    NEW_USER_TOKEN = f"{AUTH_HOST}/token/json/2/user/new"

    DOC_HOST = (
        "https://document-storage-production-dot-remarkable-production.appspot.com"
    )
    LIST_DOCS = f"{DOC_HOST}/document-storage/json/2/docs"


class Client:
    """
    The Client class is the main interface to the reMarkable API.

    It is responsible for handling the authentication and the API calls.
    """

    _config: RemarkapyConfig
    _config_filepath: pathlib.Path

    def __init__(self, configfile: pathlib.Path | str | None = None):
        """
        Create a new Client instance.

        Arguments:
            config: The configuration to use for the client. If None, the
                configuration will be loaded from the default location.

        """
        self._config, self._config_filepath = get_config_or_raise(
            configfile, return_path=True
        )
        # self._refresh_token()

    def _dump_config(self):
        """
        Save the current configuration to the config file.

        This method will write the current configuration to the
        config file specified during initialization.

        Arguments:
            None

        Returns:
            None

        Raises:
            IOError: If the config file cannot be written to.

        """
        try:
            with open(self._config_filepath, "w") as f:
                # Write two :-separated key-value pairs
                f.write(f"devicetoken: {self._config.devicetoken}\n")
                f.write(f"usertoken: {self._config.usertoken}\n")
        except IOError as e:
            logger.error(f"Failed to write config file: {e}")
            raise e

    def _post(self, url: str, data: dict, **kwargs) -> httpx.Response:
        """
        Make a POST request to the reMarkable API.

        Arguments:
            url: The URL to make the request to.
            data: The data to send in the request.

        Returns:
            The response from the server.

        Raises:
            RemarkableAPIError: If the request fails.

        """
        response = httpx.post(url, json=data, **kwargs)
        if response.status_code != 200:
            raise RemarkableAPIError(
                f"Request failed with status code {response.status_code}: {response.text}"
            )
        return response

    def _get(self, url: str, **kwargs) -> httpx.Response:
        """
        Make a GET request to the reMarkable API.

        Arguments:
            url: The URL to make the request to.

        Returns:
            The response from the server.

        Raises:
            RemarkableAPIError: If the request fails.

        """
        response = httpx.get(url, **kwargs)
        if response.status_code != 200:
            raise RemarkableAPIError(
                f"Request failed with status code {response.status_code}: {response.text}"
            )
        return response

    def _refresh_token(self):
        """
        Refresh the user token if it is expired.

        This method will check if the user token is expired and refresh it if necessary.

        https://github.com/juruen/rmapi/blob/fca802162a412f232a8a35f3a649a543ee3a86ff/auth/auth.go#L104

        Arguments:
            None

        Returns:
            None

        Raises:
            RemarkableAPIError: If the token cannot be refreshed.

        """
        url = URLS.NEW_USER_TOKEN
        headers = {
            "Authorization": f"Bearer {self._config.devicetoken}",
            "user-agent": "remarkapy",
        }
        response = self._post(url, headers=headers, data={})
        # response.text
        new_token = response.text
        self._config.devicetoken = new_token
        self._dump_config()

    def list_documents(self):
        """
        List all documents in the user's account.

        This method will make a request to the reMarkable API to retrieve
        a list of documents.

        Arguments:
            None

        Returns:
            A list of documents.

        Raises:
            RemarkableAPIError: If the request fails.

        """
        url = URLS.LIST_DOCS
        headers = {
            "Authorization": f"Bearer {self._config.usertoken}",
            "user-agent": "remarkapy",
        }
        response = self._get(url, headers=headers)
        return response.json()
