class Meta(object):
    """ Meta represents a real object expected in most
    calls by the remarkable API

    Attributes:
        ID: Id of the meta object.
        Type: Currently there are only 2 known types: DocumentType &
            CollectionType.
        visibleName: The human name of the object.
        createdTime: Time of creation of the object
        lastModified: Time of last edit of the object
        lastOpened: Last time the object was opened
        lastOpenedPage: Last page that was read
        currentPage: The current selected page of the object.
        pinned: If the object is bookmarked.
        parent: If empty, this object is in the root folder.
        files: Contains a list of files that compose the item (usually .content , .epub, .pdf, .pagedata and .metadata)

    """

    ID = ""
    Type = ""
    visibleName = ""
    createdTime = None
    lastModified = None
    lastOpened = None
    lastOpenedPage = None
    pinned = None
    parent = ""
    files = []

    def __init__(self, **kwargs):
        k_keys = self.to_dict().keys()

        for k in k_keys:
            setattr(self, k, kwargs.get(k, getattr(self, k)))

    def to_dict(self) -> dict:
        """Return a dict representation of this object.

        Used for API Calls.

        Returns
            a dict of the current object.
        """

        return {
            "ID": self.ID,
            "Type": self.Type,
            "visibleName": self.visibleName,
            "createdTime": self.createdTime,
            "lastModified": self.lastModified,
            "lastOpened": self.lastOpened,
            "lastOpenedPage": self.lastOpenedPage,
            "pinned": self.pinned,
            "parent": self.parent,
            "files": self.files
        }
