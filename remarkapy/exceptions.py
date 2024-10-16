class RemarkableAPIError(Exception):
    ...


class ExpiredToken(RemarkableAPIError):
    ...
    
class DocumentNotFound(Exception):
    """Could not found a requested document"""
    def __init__(self, msg):
        super(DocumentNotFound, self).__init__(msg)

