from .meta import Meta
from typing import Optional


class Folder(Meta):

    def __init__(self, name: Optional[str] = None, **kwargs) -> None:
        """Create a Folder instance

        Args:
            name: An optional name for this folder. It can be omitted
        """
        
        super(Folder, self).__init__(**kwargs)
        self.Type = "CollectionType"
        if name:
            self.visibleName = name
