"""The Common Vulnerabilities and Exposures (CVE) is a dictionary of publicly
known information security vulnerabilities and exposures.

CVE's common identifiers enable data exchange between security products.

More info: https://cve.mitre.org/
"""

import wget
import gzip
from lxml import objectify
import pandas as pd
import numpy as np
import dateutil.parser

class CVE(object):
    
    """A representation of the CVE database.
    """
    
    list_cve_entries = []
    
    def __init__(self, url, download=True):
        """Create a representation of the Common Vulnerabilities and
        Exposures (CVE) database from the NVD Data Feeds:
        https://nvd.nist.gov/download.cfm
        """
        self.url = url
        if(download):
            file_downladed = wget.download(url)
            self.url = str(file_downladed)
        
        self.parse_cve_database()
        
    
            
    def parse_cve_database(self):
        
        """
        Parse .gz downloaded file to list of CVEEntries
        """
        
        with gzip.open(self.url, 'rb') as f:
            file_content = f.read()
        parsed = objectify.fromstring(file_content)
        
        # for namespaces
        vuln_ns = "{http://scap.nist.gov/schema/vulnerability/0.4}"
        cvss_ns = "{http://scap.nist.gov/schema/cvss-v2/0.2}"
        
        for row in parsed.entry:
            entry_ID = str(row.attrib.get("id"))
            cve_ID = str(row[vuln_ns+"cve-id"])
            published_datetime = dateutil.parser.parse(str(row[vuln_ns+"published-datetime"])).date()
            last_modified_datetime = dateutil.parser.parse(str(row[vuln_ns+"last-modified-datetime"])).date()
            
            if row.find(vuln_ns+"cvss") is not None:
        
                score_node = row[vuln_ns+"cvss"][cvss_ns+"base_metrics"]

                score  = float(score_node[cvss_ns+"score"])
                access_vector_score = str(score_node[cvss_ns+"access-vector"])
                access_complexity_score = str(score_node[cvss_ns+"access-complexity"])
                authentication_score = str(score_node[cvss_ns+"authentication"])
                confidentiality_impact_score = str(score_node[cvss_ns+"confidentiality-impact"])
                integrity_impact_score = str(score_node[cvss_ns+"integrity-impact"])
                availability_impact_score = str(score_node[cvss_ns+"availability-impact"])
                source = str(score_node[cvss_ns+"source"])
                generated_on_datetime = str(score_node[cvss_ns+"generated-on-datetime"])
                
            else:

                score  = np.nan
                access_vector_score = np.nan
                access_complexity_score = np.nan
                authentication_score = np.nan
                confidentiality_impact_score = np.nan
                integrity_impact_score = np.nan
                availability_impact_score = np.nan
                source = np.nan
                generated_on_datetime = np.nan
                
                
            
            if row.find(vuln_ns+"cwe") is not None:
                cwe_id = str(row[vuln_ns+"cwe"].attrib.get("id"))
            else:
                cwe_id = np.nan
            
            summary = str(row[vuln_ns+"summary"])
            
            cve_entry = CVEEntry(entry_ID, cve_ID, published_datetime, last_modified_datetime,
                     score, access_vector_score, access_complexity_score,
                     authentication_score, confidentiality_impact_score,
                     integrity_impact_score, availability_impact_score,
                     source, generated_on_datetime, cwe_id, summary)
            
            self.list_cve_entries.append(cve_entry)

        
            
    def to_df(self):
        
        """Convert the database to a pandas DataFrame.
        """
        
        entry_ID_list = []
        cve_ID_list = []
        published_datetime_list = []
        last_modified_datetime_list = []
        score_list  = []
        access_vector_score_list = []
        access_complexity_score_list = []
        authentication_score_list = []
        confidentiality_impact_score_list = []
        integrity_impact_score_list = []
        availability_impact_score_list = []
        source_list = []
        generated_on_datetime_list = []
        cwe_id_list = []
        summary_list = []

        
        for i in range(0, len(self.list_cve_entries)):
            
            entry_ID_list.append(i.entry_ID)
            cve_ID_list.append(i.cve_ID)
            published_datetime_list.append(i.published_datetime)
            last_modified_datetime_list.append(i.last_modified_datetime)
            score_list.append(i.score)
            access_vector_score_list.append(i.access_vector.score)
            access_complexity_score_list.append(i.access_complexity_score)
            authentication_score_list.append(i.authentication_score)
            confidentiality_impact_score_list.append(i.confidentiality_impact_score)
            integrity_impact_score_list.append(i.integrity_impact_score)
            availability_impact_score_list.append(i.availability_impact_score)
            source_list.append(i.source)
            generated_on_datetime_list.append(i.generated_on_datetime) 
            cwe_id_list.append(i.cwe_id) 
            summary_list.append(i.summary)
        
        data = pd.DataFrame()
        data['entry_ID'] = entry_ID_list
        data['cve_ID'] = cve_ID_list
        data['published_datetime'] = published_datetime_list
        data['last_modified_datetime'] = last_modified_datetime_list
        data['score'] = score_list
        data['access_vector_score'] = access_vector_score_list
        data['access_complexity_score'] = access_complexity_score_list
        data['authentication_score'] = authentication_score_list
        data['confidentiality_impact_score'] = confidentiality_impact_score_list
        data['integrity_impact_score'] = integrity_impact_score_list
        data['availability_impact_score'] = availability_impact_score_list
        data['source'] = source_list
        data['generated_on_datetime'] = generated_on_datetime_list
        data['cwe_id'] = cwe_id_list
        data['summary'] = summary_list

        return data

    
    def __getitem__(self, ID):
        """Get the CVE entry with the given id.
        """
        for cve_entry in self.list_cve_entries:
            if(cve_entry.cve_ID == ID):
                return cve_entry
        pass

    
    def __iter__(self):
        return self

        
    def __next__(self):
        # raise StopIteration
        pass

    
class CVEEntry(object):
    
        """A entry in the CVE database.
        """
        
        
        def __init__(self, entry_id, cve_id, published_datetime, last_modified_datetime,
                     score, access_vector_score, access_complexity_score,
                     authentication_score, confidentiality_impact_score,
                     integrity_impact_score, availability_impact_score,
                     source, generated_on_datetime, cwe_id, summary):
            """Build a representation of a CVE entry from its id.
            """
            
            self.entry_ID = entry_id
            self.cve_ID = cve_id
            self.published_datetime = published_datetime
            self.last_modified_datetime = last_modified_datetime
            self.score = score
            self.access_vector_score = access_vector_score
            self.access_complexity_score = access_complexity_score
            self.authentication_score = authentication_score
            self.confidentiality_impact_score= confidentiality_impact_score
            self.integrity_impact_score = integrity_impact_score
            self.availability_impact_score = availability_impact_score
            self.source = source
            self.generated_on_datetime = generated_on_datetime
            self.cwe_id = cwe_id
            self.summary = summary
            
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
        
        def to_string(self):
            
            result = "Entry ID: " + str(self.entry_ID) + "\n"
            result += "-CVE ID: " + str(self.cve_ID) + "\n"
            result += "-Published datetime: " + str(self.published_datetime) + "\n"
            result += "-Last modified datetime: " + str(self.last_modified_datetime) + "\n"
            result += "-CVSS Score: " + str(self.score) + "\n"
            result += "\t--Access vector score: " + str(self.access_vector_score) + "\n"
            result += "\t--Access complexity score: " + str(self.access_complexity_score) + "\n"
            result += "\t--Authentication score: " + str(self.authentication_score) + "\n"
            result += "\t--Condifentiality impact score: " + str(self.confidentiality_impact_score) + "\n"
            result += "\t--Integrity impact score: " + str(self.integrity_impact_score) + "\n"
            result += "\t--Availability impact score: " + str(self.availability_impact_score) + "\n"
            result += "-Source: " + str(self.source) + "\n"
            result += "-Generated on datetime: " + str( self.generated_on_datetime) + "\n"
            result += "-CWE ID: " + str(self.cwe_id) + "\n"
            result += "-Summary: " + str(self.summary) + "\n"
            
            print(result)
        
        