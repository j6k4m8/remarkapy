from .meta import Meta

class Document(Meta):
    """ Document represents a real object expected in most
    calls by the remarkable API
    """

    def __init__(self, **kwargs):
        super(Document, self).__init__(**kwargs)
        self.Type = "DocumentType"

    def __str__(self):
        """String representation of this object"""
        return f"<rmapy.document.Document {self.ID}>"

    def __repr__(self):
        """String representation of this object"""
        return self.__str__()