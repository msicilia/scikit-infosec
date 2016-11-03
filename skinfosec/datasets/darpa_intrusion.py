"""DARPA datasets.
The original datasets are available from:
    https://www.ll.mit.edu/ideval/data/

The datasets were created by The Cyber Systems and Technology Group of MIT
Lincoln Laboratory for evaluation of computer network intrusion detection systems.

"""
import logging
import os
import urllib
import tarfile
import gzip
import shutil
import stat
import pandas as pd
from ..models.anomaly.packet_capture import classes as anon_pcap

def _parse_darpa_list_file(filename):
    result_list = []
    with open(filename) as listfile:
        for line in listfile:
            result_list.append(line.split())
    return result_list

#function to delete read-only files
def _del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)

#Match tcpdump and list file
def _match_dump_list(dumpfile, listfile):
    #process pcap file
    dataset = anon_pcap.preprocess_capture(dumpfile)
    #process tcpdump.list file
    parsed_list = _parse_darpa_list_file(listfile)
    cols = ["index", "date", "time", "duration", "service_name", "tcp_srcport",
            "tcp_dstport", "ip_src", "ip_dst", "attack_score", "attack_name"]
    parsed_list_df = pd.DataFrame(parsed_list, columns=cols)
    #Join both lists
    merge_list = ["tcp_srcport", "tcp_dstport", "ip_src", "ip_dst"]
    merged_df = dataset.merge(parsed_list_df, how='outer', on=merge_list, right_index=True)

    #Extract target data
    target = merged_df[["attack_score", "attack_name"]].copy()

    #Clean NaN values
    target['attack_score'].fillna(0, inplace=True)
    target['attack_name'].fillna('-', inplace=True)
    dataset.fillna(0, inplace=True)

    return (dataset, target)

def _download_sample_1998(darpa_directory, download_if_missing):
    #Download files
    darpa_file = urllib.URLopener()
    filepath = darpa_directory+"/sample_1998-DARPA_eval_b.tar.gz"
    url = "https://www.ll.mit.edu/ideval/data/1998/training/sample/DARPA_eval_b.tar.gz"

    if not os.path.isfile(filepath):
        if not download_if_missing:
            raise IOError("data is not locally available")
        else:
            logging.info("Downloading : %s to %s", url, filepath)
            darpa_file.retrieve(url, filepath)
            logging.info("Download completed")
    #End of Download

    #File Extraction
    #extracting first file (tar.gz)
    logging.info("Extracting %s", filepath)
    tar_file = tarfile.open(filepath, "r:gz")
    tar_file.extractall(path=darpa_directory)
    tar_file.close()
    filepath = darpa_directory+"/DARPA_eval_b/sample_data01.tcpdump.gz"
    #extracting second file (gz)
    logging.info("Extracting %s", filepath)
    gz_file = gzip.open(filepath, 'rb')
    dumpfile = darpa_directory+"/sample_1998-sample_data01.tcpdump"
    output_file = open(dumpfile, 'wb')
    output_file.write(gz_file.read())
    gz_file.close()
    output_file.close()
    #Moving list file
    listfile = darpa_directory+"/sample_1998-sample_data01.tcpdump.list"
    shutil.move(darpa_directory+"/DARPA_eval_b/tcpdump.list", listfile)
    #deleting intermediate folder
    try:
        logging.info("deleting "+darpa_directory+"/DARPA_eval_b")
        shutil.rmtree(darpa_directory+"/DARPA_eval_b")
    except OSError:
        pass
    return (dumpfile, listfile)

def _download_train_4hour_1998(darpa_directory, download_if_missing):
    darpa_file = urllib.URLopener()
    filepath = darpa_directory+"/train_4hour_1998-tcpdump.gz"
    url = "https://www.ll.mit.edu/ideval/data/1998/training/four_hours/tcpdump.gz"
    if not os.path.isfile(filepath):
        if not download_if_missing:
            raise IOError("data is not locally available")
        else:
            logging.info("Downloading : %s to %s", url, filepath)
            darpa_file.retrieve(url, filepath)
            logging.info("Download completed")
    #End of Download

    #File Extraction
    #extracting first file (tar)
    logging.info("Extracting %s", filepath)
    tar_file = tarfile.open(filepath, "r:")
    tar_file.extractall(path=darpa_directory)
    tar_file.close()
    filepath = darpa_directory+"/outside.tcpdump.gz"
    #extracting second file (gz)
    logging.info("Extracting %s", filepath)
    gz_file = gzip.open(filepath, 'rb')
    dumpfile = darpa_directory+"/train_4hour_1998-outside.tcpdump"
    output_file = open(dumpfile, 'wb')
    output_file.write(gz_file.read())
    gz_file.close()
    output_file.close()
    #deleting intermediate gzip file
    try:
        logging.info("deleting "+filepath)
        os.remove(filepath)
    except OSError:
        pass
    #Retrieving list file
    url = "https://www.ll.mit.edu/ideval/data/1998/training/four_hours/fourhour.tar.gz"
    filepath = darpa_directory+"/train_4hour_1998-fourhour.tar.gz"
    if not os.path.isfile(filepath):
        if not download_if_missing:
            raise IOError("data is not locally available")
        else:
            logging.info("Downloading : %s to %s", url, filepath)
            darpa_file.retrieve(url, filepath)
            logging.info("Download completed")

    logging.info("Extracting %s", filepath)
    tar_file = tarfile.open(filepath, "r:gz")
    tar_file.extractall(path=darpa_directory)
    tar_file.close()
    listfile = darpa_directory+"/train_4hour_1998-outside.tcpdump.list"
    shutil.move(darpa_directory+"/fourhour/data/tcpdump.list",
                darpa_directory+"/train_4hour_1998-outside.tcpdump.list")
    #deleting intermediate folder
    try:
        logging.info("deleting "+darpa_directory+"/fourhour")
        shutil.rmtree(darpa_directory+"/fourhour", onerror=_del_rw)
    except OSError:
        pass
    return (dumpfile, listfile)

def _download_train_w1_w2_1998(subset, darpa_directory, download_if_missing):
    w1_w2_1998 = {'train_w1_mon_1998' : ['train_week1_monday', 'monday'],
                  'train_w1_tue_1998' : ['train_week1_tuesday', 'tuesday'],
                  'train_w1_wed_1998' : ['train_week1_wednesday', 'wednesday'],
                  'train_w1_thu_1998' : ['train_week1_thursday', 'thursday'],
                  'train_w1_fri_1998' : ['train_week1_friday', 'friday'],
                  'train_w2_mon_1998' : ['train_week2_monday', 'monday'],
                  'train_w2_tue_1998' : ['train_week2_tuesday', 'tuesday'],
                  'train_w2_wed_1998' : ['train_week2_wednesday', 'wednesday'],
                  'train_w2_thu_1998' : ['train_week2_thursday', 'thursday'],
                  'train_w2_fri_1998' : ['train_week2_friday', 'friday']}

    darpa_file = urllib.URLopener()
    if subset in w1_w2_1998:
        logging.info("Subset: %s", subset)
        filepath = darpa_directory+"/"+w1_w2_1998[subset][0]+"_1998.tar"
        dumpfile = darpa_directory+"/"+w1_w2_1998[subset][0]+"_1998-outside.tcpdump"
        listfile = darpa_directory+"/"+w1_w2_1998[subset][0]+"1998-outside.tcpdump.list"
        inter_dir = w1_w2_1998[subset][1]
        url = "https://www.ll.mit.edu/ideval/data/1998/training/week1/"+w1_w2_1998[subset][1]+".tar"
    else:
        raise AttributeError("_download_train_w1_w2_1998: subset not valid")
    if not os.path.isfile(filepath):
        if not download_if_missing:
            raise IOError("data is not locally available")
        else:
            logging.info("Downloading : %s to %s", url, filepath)
            darpa_file.retrieve(url, filepath)
            logging.info("Download completed")
            #End of Download

    #File Extraction
    #extracting first file (tar)
    logging.info("Extracting %s", filepath)
    tar_file = tarfile.open(filepath, "r:")
    tar_file.extractall(path=darpa_directory)
    tar_file.close()
    #extracting dump file (gz)
    filepath = darpa_directory+"/"+inter_dir+"/tcpdump.gz"
    logging.info("Extracting %s", filepath)
    gz_file = gzip.open(filepath, 'rb')
    output_file = open(dumpfile, 'wb')
    output_file.write(gz_file.read())
    gz_file.close()
    output_file.close()
    #extracting list file (gz)
    filepath = darpa_directory+"/"+inter_dir+"/tcpdump.list.gz"
    logging.info("Extracting %s", filepath)
    gz_file = gzip.open(filepath, 'rb')
    output_file = open(listfile, 'wb')
    output_file.write(gz_file.read())
    gz_file.close()
    output_file.close()
    #deleting intermediate folder
    try:
        logging.info("deleting "+darpa_directory+"/"+inter_dir)
        shutil.rmtree(darpa_directory+"/"+inter_dir, onerror=_del_rw)
    except OSError:
        pass
    return (dumpfile, listfile)

def _download_train_w3_w7_1998(subset, darpa_directory, download_if_missing):
    w3_1998 = {'train_w3_mon_1998' : ['train_week3_monday', 'monday', 'week3'],
               'train_w3_tue_1998' : ['train_week3_tuesday', 'tuesday', 'week3'],
               'train_w3_wed_1998' : ['train_week3_wednesday', 'wednesday', 'week3'],
               'train_w3_thu_1998' : ['train_week3_thursday', 'thursday', 'week3'],
               'train_w3_fri_1998' : ['train_week3_friday', 'friday', 'week3'],
               'train_w4_tue_1998' : ['train_week4_tuesday', 'tuesday', 'week4'],
               'train_w4_wed_1998' : ['train_week4_wednesday', 'wednesday', 'week4'],
               'train_w4_thu_1998' : ['train_week4_thursday', 'thursday', 'week4'],
               'train_w4_fri_1998' : ['train_week4_friday', 'friday', 'week4'],
               'train_w5_mon_1998' : ['train_week5_monday', 'monday', 'week5'],
               'train_w5_tue_1998' : ['train_week5_tuesday', 'tuesday', 'week5'],
               'train_w5_wed_1998' : ['train_week5_wednesday', 'wednesday', 'week5'],
               'train_w5_thu_1998' : ['train_week5_thursday', 'thursday', 'week5'],
               'train_w5_fri_1998' : ['train_week5_friday', 'friday', 'week5'],
               'train_w6_mon_1998' : ['train_week6_monday', 'monday', 'week6'],
               'train_w6_tue_1998' : ['train_week6_tuesday', 'tuesday', 'week6'],
               'train_w6_wed_1998' : ['train_week6_wednesday', 'wednesday', 'week6'],
               'train_w6_thu_1998' : ['train_week6_thursday', 'thursday', 'week6'],
               'train_w6_fri_1998' : ['train_week6_friday', 'friday', 'week7'],
               'train_w7_mon_1998' : ['train_week7_monday', 'monday', 'week7'],
               'train_w7_tue_1998' : ['train_week7_tuesday', 'tuesday', 'week7'],
               'train_w7_wed_1998' : ['train_week7_wednesday', 'wednesday', 'week7'],
               'train_w7_thu_1998' : ['train_week7_thursday', 'thursday', 'week7'],
               'train_w7_fri_1998' : ['train_week7_friday', 'friday', 'week7']}

    darpa_file = urllib.URLopener()
    if subset in w3_1998:
        logging.info("Subset: %s", subset)
        filepath = darpa_directory+"/"+w3_1998[subset][0]+"_1998-tcpdump.gz"
        filepath2 = darpa_directory+"/"+w3_1998[subset][0]+"_1998-tcpdump.list.gz"
        dumpfile = darpa_directory+"/"+w3_1998[subset][0]+"_1998-outside.tcpdump"
        listfile = darpa_directory+"/"+w3_1998[subset][0]+"_1998-outside.tcpdump.list"
        url = ("https://www.ll.mit.edu/ideval/data/1998/training/"
               +w3_1998[subset][2]+"/"+w3_1998[subset][1]+"/tcpdump.gz")
        url2 = ("https://www.ll.mit.edu/ideval/data/1998/training/"
                +w3_1998[subset][2]+"/"+w3_1998[subset][1]+"/tcpdump.list.gz")
    else:
        raise AttributeError("_download_train_w1_w2_1998: subset not valid")

    #Downloading files'
    if not os.path.isfile(filepath):
        if not download_if_missing:
            raise IOError("data is not locally available")
        else:
            logging.info("Downloading : %s to %s", url, filepath)
            darpa_file.retrieve(url, filepath)
            logging.info("Download completed")
    if not os.path.isfile(filepath2):
        if not download_if_missing:
            raise IOError("data is not locally available")
        else:
            logging.info("Downloading : %s to %s", url2, filepath2)
            darpa_file.retrieve(url2, filepath2)
            logging.info("Download completed")
    #End of Download

    #extracting dump file (gz)
    logging.info("Extracting %s", filepath)
    gz_file = gzip.open(filepath, 'rb')
    output_file = open(dumpfile, 'wb')
    output_file.write(gz_file.read())
    gz_file.close()
    output_file.close()
    #extracting list file (gz)
    logging.info("Extracting %s", filepath2)
    gz_file = gzip.open(filepath2, 'rb')
    output_file = open(listfile, 'wb')
    output_file.write(gz_file.read())
    gz_file.close()
    output_file.close()

    return (dumpfile, listfile)

def _download_test_w1_w2_1998(subset, darpa_directory, download_if_missing):
    w1_2_1998 = {'test_w1_mon_1998' : ['test_week1_monday', 'monday', 'week1'],
                 'test_w1_tue_1998' : ['test_week1_tuesday', 'tuesday', 'week1'],
                 'test_w1_wed_1998' : ['test_week1_wednesday', 'wednesday', 'week1'],
                 'test_w1_thu_1998' : ['test_week1_thursday', 'thursday', 'week1'],
                 'test_w1_fri_1998' : ['test_week1_friday', 'friday', 'week1'],
                 'test_w2_mon_1998' : ['test_week2_monday', 'monday', 'week2'],
                 'test_w2_tue_1998' : ['test_week2_tuesday', 'tuesday', 'week2'],
                 'test_w2_wed_1998' : ['test_week2_wednesday', 'wednesday', 'week2'],
                 'test_w2_thu_1998' : ['test_week2_thursday', 'thursday', 'week2'],
                 'test_w2_fri_1998' : ['test_week2_friday', 'friday', 'week2']}

    darpa_file = urllib.URLopener()
    if subset in w1_2_1998:
        logging.info("Subset: %s", subset)
        filepath = darpa_directory+"/"+w1_2_1998[subset][0]+"_1998-tcpdump.gz"
        filepath2 = darpa_directory+"/"+w1_2_1998[subset][0]+"_1998-tcpdump.list.gz"
        dumpfile = darpa_directory+"/"+w1_2_1998[subset][0]+"_1998-outside.tcpdump"
        listfile = darpa_directory+"/"+w1_2_1998[subset][0]+"_1998-outside.tcpdump.list"
        url = ("https://www.ll.mit.edu/ideval/data/1998/testing/"
               +w1_2_1998[subset][2]+"/"+w1_2_1998[subset][1]+"/tcpdump.gz")
        url2 = ("https://www.ll.mit.edu/ideval/data/1998/testing/"
                +w1_2_1998[subset][2]+"/"+w1_2_1998[subset][1]+"/tcpdump.list.gz")
    else:
        raise AttributeError("_download_test_w1_w2_1998: subset not valid")

    #Downloading files'
    if not os.path.isfile(filepath):
        if not download_if_missing:
            raise IOError("data is not locally available")
        else:
            logging.info("Downloading : %s to %s", url, filepath)
            darpa_file.retrieve(url, filepath)
            logging.info("Download completed")
    if not os.path.isfile(filepath2):
        if not download_if_missing:
            raise IOError("data is not locally available")
        else:
            logging.info("Downloading : %s to %s", url2, filepath2)
            darpa_file.retrieve(url2, filepath2)
            logging.info("Download completed")
    #End of Download

    #extracting dump file (gz)
    logging.info("Extracting %s", filepath)
    gz_file = gzip.open(filepath, 'rb')
    output_file = open(dumpfile, 'wb')
    output_file.write(gz_file.read())
    gz_file.close()
    output_file.close()
    #extracting list file (gz)
    logging.info("Extracting %s", filepath2)
    gz_file = gzip.open(filepath2, 'rb')
    output_file = open(listfile, 'wb')
    output_file.write(gz_file.read())
    gz_file.close()
    output_file.close()

    return (dumpfile, listfile)


def fetch_darpa_intrusion(subset='sample_1998', data_home=None,
                          download_if_missing=True):
    """Loader for the intrusion detection datasets from DARPA. (tcpdump files)
    Parameters
    ----------
    data_home : optional, default: None
        Specify another download and cache folder for the datasets. By default
        all scikit learn data is stored in '~/scikit_infosec_data' subfolders.

    download_if_missing : optional, default: True
        If False, raise a IOError if the data is not locally available instead
        of trying to download the data from the source site.

    subset : optional, default: 'sample_1998'
        Select the dataset to load:
        'sample_1998' - sample of the network traffic and audit logs that
        were used for evaluating systems in 1998.
        'train_4hour_1998' - Four-Hour Subset of Training Data
        'train_w1_mon_1998' - 1998 Training Data - Week 1 -	Monday Data
        'train_w1_tue_1998' - 1998 Training Data - Week 1 - Tuesday Data
        'train_w1_wed_1998' - 1998 Training Data - Week 1 - Wednesday Data
        'train_w1_thu_1998' - 1998 Training Data - Week 1 - Thursday Data
        'train_w1_fri_1998' - 1998 Training Data - Week 1 - Friday Data
        ...
        'train_w[X]_mon_1998' - 1998 Training Data - Week X - Monday Data
        ...
        'train_w[X]_fri_1998' - 1998 Training Data - Week X - Friday Data
        For training data, there are 7 weeks available: X = [1 2 3 4 5 6 7],
        from monday to friday
        OBS: week 4, monday is not available
        'test_w1_mon_1998' - 1998 Testing Data - Week 1 - Monday Data
        ...
        'test_w2_fri_1998' - 1998 Testing Data - Week 2 - Friday Data
        For testing data, there are 2 weeks available: X = [1 2], from monday
        to friday


    """
    #Data folder checks
    if data_home is None:
        base_directory = os.path.expanduser("~")
    else:
        base_directory = data_home
    base_directory += "/scikit_infosec_data"
    if not os.path.exists(base_directory):
        os.makedirs(base_directory)
        logging.info("Creating directory: %s", base_directory)
    darpa_directory = base_directory+"/darpa_intrusion"
    if not os.path.exists(darpa_directory):
        os.makedirs(darpa_directory)
        logging.info("Creating directory: %s", darpa_directory)
    #End of data folder checks

    w1_w2_1998 = ['train_w1_mon_1998', 'train_w1_tue_1998', 'train_w1_wed_1998',
                  'train_w1_thu_1998', 'train_w1_fri_1998', 'train_w2_mon_1998',
                  'train_w2_tue_1998', 'train_w2_wed_1998', 'train_w2_thu_1998',
                  'train_w2_fri_1998']
    w3_w7_1998 = ['train_w3_mon_1998', 'train_w3_tue_1998', 'train_w3_wed_1998',
                  'train_w3_thu_1998', 'train_w3_fri_1998', 'train_w4_tue_1998',
                  'train_w4_wed_1998', 'train_w4_thu_1998', 'train_w4_fri_1998',
                  'train_w5_mon_1998', 'train_w5_tue_1998', 'train_w5_wed_1998',
                  'train_w5_thu_1998', 'train_w5_fri_1998', 'train_w6_mon_1998',
                  'train_w6_tue_1998', 'train_w6_wed_1998', 'train_w6_thu_1998',
                  'train_w6_fri_1998', 'train_w7_mon_1998', 'train_w7_tue_1998',
                  'train_w7_wed_1998', 'train_w7_thu_1998', 'train_w7_fri_1998']

    w1_w2_98_test = ['test_w1_mon_1998', 'test_w1_tue_1998', 'test_w1_wed_1998',
                     'test_w1_thu_1998', 'test_w1_fri_1998', 'test_w2_mon_1998',
                     'test_w2_tue_1998', 'test_w2_wed_1998', 'test_w2_thu_1998',
                     'test_w2_fri_1998']

    #Download files
    if subset == 'sample_1998':
        files = _download_sample_1998(darpa_directory, download_if_missing)
    elif subset == 'train_4hour_1998':
        files = _download_train_4hour_1998(darpa_directory, download_if_missing)
    elif subset in w1_w2_1998:
        files = _download_train_w1_w2_1998(subset, darpa_directory,
                                           download_if_missing)
    elif subset in w3_w7_1998:
        files = _download_train_w3_w7_1998(subset, darpa_directory,
                                           download_if_missing)
    elif subset in w1_w2_98_test:
        files = _download_test_w1_w2_1998(subset, darpa_directory,
                                          download_if_missing)
    else:
        raise AttributeError("fetch_darpa_intrusion: Invalid subset")

    dumpfile = files[0]
    listfile = files[1]

    return _match_dump_list(dumpfile, listfile)
