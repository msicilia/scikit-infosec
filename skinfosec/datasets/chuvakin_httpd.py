"""Dr. Anton Chuvakin log files.
The original files are available from:
    http://log-sharing.dreamhosters.com/

The logs are collected from real systems, some contain evidence of compromise
and other malicious activity. Wherever possible, the logs are NOT sanitized,
anonymized or modified in any way (just as they came from the logging system)

"""
import logging
import os
import urllib
import tarfile
import shutil
from ..models.anomaly.web import classes as anon_web

def _fetch_extract(chuvakin_directory, final_file_str, tarfile_str):
    url = 'http://log-sharing.dreamhosters.com/hnet-hon-var-log-02282006.tgz'
    if not os.path.isfile(tarfile_str):
        chuvakin_download = urllib.URLopener()
        logging.info("Downloading : %s to %s", url, tarfile_str)
        chuvakin_download.retrieve(url, tarfile_str)
        logging.info("Download completed")

    #Extracting tar file (httpd log files only)
    logging.info("Extracting tar file: %s", tarfile_str)
    with tarfile.open(tarfile_str, "r:gz") as tar:
        subdir_and_files = [
            tarinfo for tarinfo in tar.getmembers()
            if tarinfo.name.startswith("var/log/httpd/access")]
        tmpdir = chuvakin_directory+"/chuvakin_tmp"
        if not os.path.exists(tmpdir):
            logging.info("Creating temp folder: "+tmpdir)
            os.makedirs(tmpdir)
        tar.extractall(members=subdir_and_files, path=tmpdir)
        tar.close()

        #Merge files
        logging.info("Merging files in one access_log file")
        with open(final_file_str, 'wb') as final_file_h:
            for number in range(31, 0, -1):
                with open(tmpdir+"/var/log/httpd/access_log."+str(number), 'rb') as tmpfile_h:
                    shutil.copyfileobj(tmpfile_h, final_file_h)
            with open(tmpdir+"/var/log/httpd/access_log", 'rb') as tmpfile_h:
                shutil.copyfileobj(tmpfile_h, final_file_h)
    #deleting temp folder
    try:
        logging.info("Deleting temp folder: %s", tmpdir)
        shutil.rmtree(tmpdir)
    except OSError:
        pass
    logging.info("Deleting tar file: %s", tarfile_str)
    os.remove(tarfile_str)
    if not os.path.isfile(final_file_str):
        raise IOError("Error opening %s", final_file_str)
    return True

def fetch_chuvakin_logs(data_home=None, download_if_missing=True):
    """Fetcher and Loader for Dr. Anton Chuvakin log files. (httpd logs)

    Parameters
    ----------
    data_home : optional, default: None
        Specify another download and cache folder for the datasets. By default
        all scikit learn data is stored in '~/scikit_infosec_data' subfolders.

    download_if_missing : optional, default: True
        If False, raise a IOError if the data is not locally available instead
        of trying to download the data from the source site.

    """
    #Data folder checks
    if data_home is None:
        base_directory = os.path.expanduser("~")
    else:
        base_directory = data_home
    base_directory += "/scikit_infosec_data"
    if not os.path.exists(base_directory):
        logging.info("Creating directory: %s", base_directory)
        os.makedirs(base_directory)
    chuvakin_directory = base_directory+"/chuvakin_logs"
    if not os.path.exists(chuvakin_directory):
        logging.info("Creating directory: %s", chuvakin_directory)
        os.makedirs(chuvakin_directory)
    #End of data folder checks

    final_file_str = chuvakin_directory+"/access_log"
    if not os.path.isfile(final_file_str):
        tarfile_str = chuvakin_directory+"/hnet-hon-var-log-02282006.tgz"
        if not os.path.isfile(tarfile_str) and not download_if_missing:
            raise IOError("Data is not locally available")
        else:
            _fetch_extract(chuvakin_directory, final_file_str, tarfile_str)
    else:
        logging.info("File exists: %s: ", final_file_str)

    with open(final_file_str) as data:
        dataset = anon_web.preprocess_requests(data, log_format='Combined')

    return dataset
