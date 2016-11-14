"""The Common Vulnerabilities and Exposures (CVE) is a dictionary of publicly
known information security vulnerabilities and exposures.

CVE’s common identifiers enable data exchange between security products.

More info: https://cve.mitre.org/
"""

import wget
import gzip

class CVE(object):
    """A representation of the CVE database.
    """
    def __init__(self, cache=True):
        """Create a representation of the Common Vulnerabilities and
        Exposures (CVE) database from the NVD Data Feeds:
        https://nvd.nist.gov/download.cfm
        """
        pass

    def to_df(self):
        """Convert the database to a pandas DataFrame.
        """
        pass

    def __getattr__(self, key):
        """Get the CVE entry with the given id.
        """
        pass

     def __iter__(self):
        return self

     def __next__(self):
        # raise StopIteration
        pass

class CVEEntry(object):
        """A entry in the CVE database.
        """
        def __init__(self, cve_id):
            """Build a representation of a CVE entry from its id.
            """
            pass

        def published(self):
            pass

        def last_modified(self):
            pass

        def cvss(self):
            pass

        def summary(self):
            pass

        def cpe_names(self):
            """Get the list of CPE names for the vulnerability.
            """
            pass
