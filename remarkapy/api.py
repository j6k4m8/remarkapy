"""
This module contains the logic for main reMarkable API.

The API calls themselves are handled by the Client class.
"""

import logging
import pathlib
import uuid
import httpx

from .configfile import RemarkapyConfig, get_config_or_raise
from .entries import Entry, parse_entries

logger = logging.getLogger(__name__)


class RemarkableAPIError(Exception):
    ...


class ExpiredToken(RemarkableAPIError):
    ...


class URLS:
    # https://github.com/juruen/rmapi/blob/master/config/url.go
    # NOTE Webapp endpoints could be fetched on every init
    # https://eu.tectonic.remarkable.com/discovery/v1/endpoints
    AUTH_HOST = "https://webapp-prod.cloud.remarkable.engineering"
    REGISTER_DEVICE = f"{AUTH_HOST}/token/json/2/device/new"
    NEW_USER_TOKEN = f"{AUTH_HOST}/token/json/2/user/new"

    SYNC_URL = "https://internal.cloud.remarkable.com"
    CLOUD_HOST = "https://eu.tectonic.remarkable.com"
    LIST_ROOT = f"{CLOUD_HOST}/sync/v4/root"
    GET_FILE = f"{CLOUD_HOST}/sync/v3/files/"


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
        self._refresh_token()

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
        # print(f"Device: [{self._config.devicetoken}]")
        # print(f"User: [{self._config.usertoken}]")
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

        # Device has been unpaired
        # NOTE could call device registration method
        if response.status_code == 401:
            raise ExpiredToken(
                f"Device token has expired. Was the device unpaired?")
        elif response.status_code != 200:
            raise RemarkableAPIError(
                f"Request failed with status code {response.status_code} when POSTing to {url}: {response.text}"
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
                f"Request failed with status code {response.status_code} when GETting from {url}: {response.text}"
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

        if not self._config.devicetoken:
            self.register_device_wizard()

        url = URLS.NEW_USER_TOKEN
        headers = {
            "Authorization": f"Bearer {self._config.devicetoken}",
            "user-agent": "remarkapy",
        }

        response = self._post(url, headers=headers, data={})
        new_token = response.text
        self._config.usertoken = new_token
        self._dump_config()

    def _register_device(self, code: str):
        """
        Registers as an app/device on Remarkable Cloud with a random UUID

        Must provide a valid deviceDesc otherwise it would fail

        Arguments:
            code: Verification code from https://my.remarkable.com/pair/app

        Returns:
            A device token

        Raises:
            RemarkableAPIError: If the request fails.

        """

        data = {
            "code": code,
            "deviceDesc": "desktop-macos",
            "deviceID": str(uuid.uuid4()),
            "secret": ""
        }

        headers = {'User-Agent': 'desktop/3.14.0.887 (macos 15.0)'}

        url = URLS.REGISTER_DEVICE
        response = self._post(url, headers=headers, data=data, timeout=20)

        if response.status_code == 200:
            device_token = response.text
            self._config.devicetoken = device_token
            self._dump_config()
            return True, "Device registered"
        else:
            return False, response.text

    def register_device_wizard(self):

        print('\n=== REMARKABLE CLOUD ===')
        print(
            'Please visit https://my.remarkable.com/pair/app and enter the code shown')

        code = ''

        while len(code) != 8:
            try:
                code = input('Verification code: ').strip()
            except KeyboardInterrupt:
                raise KeyboardInterrupt

        res, msg = self._register_device(code)

        print(msg)

    def list_documents(self) -> list[Entry]:
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

        url = URLS.LIST_ROOT
        headers = {
            "Authorization": f"Bearer {self._config.usertoken}",
            "user-agent": "remarkapy",
        }

        response = self._get(url, headers=headers)
        if not response.status_code == 200:
            raise RemarkableAPIError(
                f"Request failed with status code {response.status_code} when listing documents: {response.text}"
            )

        # NOTE we could store this hash somewhere as it probably changes only
        # when a folder/file gets created/modified (if we decide to cache some data)
        root_hash = response.json()['hash']

        # List doc hashes on root folder
        url = URLS.GET_FILE + root_hash
        response = self._get(url, headers=headers)
        obj_list = response.text.splitlines()

        root = {}

        # Add a file or a folder to a specific parent_hash or to root
        def add_item_to_folder(folders, folder_hash: str, parent_hash: str = "", visible_name: str = "", metadata: dict = None, files: list = None):

            # Trash is a special folder which doesn''t have a specific hash, just "trash"
            if parent_hash == "trash":

                if "trash" not in folders:
                    folders["trash"] = {
                        "visibleName": "Trash",
                        "subfolders": {},
                        "docs": {}
                    }

            # Recursively find or create a folder
            def find_or_create_folder(folders, target_hash, parent_hash, visible_name):
                # If no parent, add at root level
                if not parent_hash:
                    if target_hash not in folders:
                        folders[target_hash] = {
                            'name': visible_name,
                        }

                        if not metadata:
                            folders[target_hash]['subfolders'] = {}

                    return folders[target_hash]

                for existing_folder_hash, folder_data in folders.items():

                    if existing_folder_hash == parent_hash:
                        if target_hash not in folder_data['subfolders']:
                            folder_data['subfolders'][target_hash] = {
                                'name': visible_name,
                            }
                            if not metadata:
                                folder_data['subfolders'][target_hash]['subfolders'] = {
                                }

                        return folder_data['subfolders'][target_hash]

                    if 'subfolders' in folder_data:
                        found_folder = find_or_create_folder(
                            folder_data['subfolders'], target_hash, parent_hash, visible_name)
                        if found_folder:
                            return found_folder

                return None

            current_folder = find_or_create_folder(
                folders, folder_hash, parent_hash, visible_name)

            print(
                f"Trying to find or create folder: {folder_hash} - parent hash: {parent_hash}")

            if current_folder is None:
                raise (
                    f"Unable to find or create folder with hash: {folder_hash}")

            # Add metadata or files to item/folder
            if metadata:
                current_folder['metadata'] = metadata
                current_folder['files'] = {}

                if files:
                    current_folder['files'] = files

                return True

            return False

        # First pass: Collect all folders and their relationships
        for i in range(1, len(obj_list)):
            obj_data = obj_list[i].split(':')
            obj_hash = obj_data[0]
            obj_folder_hash = obj_data[2]

            url = URLS.GET_FILE + obj_hash
            response = self._get(url, headers=headers)

            file_data = response.text.splitlines()

            # Files
            files = []
            current_item_key = ''
            current_parent_key = ''

            for j in range(1, len(file_data)):
                obj_data = file_data[j].split(':')
                obj_hash = obj_data[0]
                obj_name = obj_data[2]

                print('Hash %s | ****%s | Folder hash %s' %
                      (obj_hash, obj_name[-25:], obj_folder_hash))

                # Only process metadata if it's a metadata file
                if '.metadata' in obj_name:
                    url = URLS.GET_FILE + obj_hash
                    response = self._get(url, headers=headers)

                    json_data = response.json()

                    if 'type' not in json_data:
                        continue

                    # Handle folders (CollectionType)
                    # Will look for a parent hash, if any
                    if json_data['type'] == 'CollectionType':
                        add_item_to_folder(
                            folders=root, parent_hash=json_data['parent'], folder_hash=obj_folder_hash, visible_name=json_data['visibleName'])
                        continue

                    # Regular document metadata processing
                    current_item_key = json_data['visibleName']
                    # Get the parent folder using hash
                    current_parent_key = json_data['parent']

                # Collect file information
                file_info = {
                    'hash': obj_hash,
                    'fileName': obj_name,
                    'format': obj_name.split('.')[-1]
                }

                files.append(file_info)

            add_item_to_folder(folders=root, parent_hash=json_data['parent'], folder_hash=obj_folder_hash,
                               visible_name=json_data['visibleName'], metadata=json_data, files=files)

        return root
        # return parse_entries(results, fail_method="warn")
