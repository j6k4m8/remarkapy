"""
This module contains the logic for main reMarkable API.

The API calls themselves are handled by the Client class.
"""

import logging
import pathlib
import uuid
import httpx
from datetime import datetime
import crc32c
import base64
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

    # SYNC_URL = "https://internal.cloud.remarkable.com"
    CLOUD_HOST = "https://eu.tectonic.remarkable.com"
    LIST_ROOT = f"{CLOUD_HOST}/sync/v4/root"
    GET_FILE = f"{CLOUD_HOST}/sync/v3/files/"

    # SYNC
    SYNC_FILE = f"{CLOUD_HOST}/sync/v3/root"


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

    def _put(self, url: str, **kwargs) -> httpx.Response:
        """
        Make a PUT request to the reMarkable API.

        Arguments:
            url: The URL to make the request to.

        Returns:
            The response from the server.

        Raises:
            RemarkableAPIError: If the request fails.

        """
        response = httpx.put(url, **kwargs)
        if response.status_code != 200:
            raise RemarkableAPIError(
                f"Request failed with status code {response.status_code} when PUTting to {url}: {response.text}"
            )
        return response

    def _sync_file(self, file_hash:str):

        """
        Refresh the server side cached copy. This method should probably be called after any create, update or deletion of a file.

        Arguments:
            hash: hash of the file you uploaded / modified

        Returns:
            None

        Raises:
            RemarkableAPIError: 
        """

        if len(file_hash) != 64:
            raise ValueError(f"Expected a 64 char hash")

        # Get current time in microseconds
        now = datetime.now()
        timestamp_ms = int(now.timestamp() * 1_000_000)

        data = {
            "broadcast": True,
            "generation": timestamp_ms,
            "hash": file_hash
        }

        headers = {
            "Authorization": f"Bearer {self._config.usertoken}",
            "user-agent": "remarkapy",
            "rm-filename": "roothash",
        }
    
        url = URLS.SYNC_FILE
        self._put(url, headers=headers, json=data)

    def _calculate_checksum(self, input_file:bytes):

        # Calculate CRC32C checksum
        crc32c_checksum = crc32c.crc32c(input_file)

        # Convert to base64
        crc32c_bytes = crc32c_checksum.to_bytes(4, byteorder='big')
        crc32c_base64 = base64.b64encode(crc32c_bytes).decode('utf-8')

        # print(f"CRC32C Checksum (Base64): {crc32c_base64}")

        return crc32c_base64

    def _preparare_metadata(self, metadata:dict):

        """

        Arguments:
            metadata : dict

        Returns:
            A formatted metadata string that can be CRCd with _calculate_checksum()

        Raises:
            None

        """

        # trying this approach to maintain indentation. Otherwise CRC would mismatach
        # TODO find a better solution?
        metadata_raw = f'''{{
    "createdTime": "{metadata['createdTime']}",
    "lastModified": "{metadata['lastModified']}",
    "lastOpened": "{metadata['lastOpened']}",
    "lastOpenedPage": "{metadata['lastOpenedPage']}",
    "parent": "{metadata['parent']}",
    "pinned": {metadata['pinned']},
    "type": "{metadata['type']}",
    "visibleName": "{metadata['visibleName']}"
}}
'''
        return metadata_raw

    def rename_file(self, metadata_hash:str, new_name:str):

        # Should get file first and extract metadata
        response = self._get_file_by_hash(obj_hash=metadata_hash)

        metadata = response.json()
        
        # Replace name without changing any other info
        metadata['visibleName'] = new_name
        metadata_raw = self._preparare_metadata(metadata)

        # Convert str to bytes
        input_bytes = metadata_raw.encode('utf-8')

        checksum = self._calculate_checksum(input_bytes)

        print(checksum)


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

    def _get_file_by_hash(self, obj_hash:str):
        
        headers = {
            "Authorization": f"Bearer {self._config.usertoken}",
            "user-agent": "remarkapy",
        }

        url = URLS.GET_FILE + obj_hash
        return self._get(url, headers=headers)

    def _get_root_folder(self):
        headers = {
            "Authorization": f"Bearer {self._config.usertoken}",
            "user-agent": "remarkapy",
        }

        url = URLS.LIST_ROOT
        return self._get(url, headers=headers)

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

        response = self._get_root_folder()

        # NOTE we could store this hash somewhere as it probably changes only
        # when a folder/file gets created/modified (if we decide to cache some data)
        root_hash = response.json()['hash']

        # List doc hashes on root folder
        response = self._get_file_by_hash(obj_hash=root_hash)
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

            response = self._get_file_by_hash(obj_hash=obj_hash)
            file_data = response.text.splitlines()

            # Files
            files = []
            current_item_key = ''
            current_parent_key = ''

            for j in range(1, len(file_data)):
                obj_data = file_data[j].split(':')
                obj_hash = obj_data[0]
                obj_name = obj_data[2]

                print('Hash %s | %s | Folder hash %s' %
                      (obj_hash, obj_name, obj_folder_hash))

                # Only process metadata if it's a metadata file
                if '.metadata' in obj_name:
                    response = self._get_file_by_hash(obj_hash=obj_hash)

                    json_data = response.json()

                    print(json_data)

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
