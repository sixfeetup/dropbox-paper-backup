#!/usr/bin/env python3
# encoding: utf-8

""" Dropbox Backup

Usage:
  {cmd} [--token=TOKEN] [--logfile=PATH] [--verbose] [markdown|html] <target>  

Options:
  -t --token=TOKEN    The access token for the dropbox account. Omit to get a new token.
  -l --logfile=PATH   Log to the specified file. 
  -v --verbose        Be more verbose.
  markdown|html       Export either as "html" or as "markdown". Do both if omitted.
  <target>            The path to store the backup in.
  
"""

import io
import logging
import os
import re
import sys
import traceback
import unicodedata
import urllib.parse
import webbrowser
from contextlib import contextmanager

import docopt
import dropbox
import requests
import requests.packages.urllib3

# API-Description: https://www.dropbox.com/developers/documentation/http/documentation#paper-docs-list
APP_KEY = "yb0prv4vj0ckhdt"
APP_SECRET = b'J,/ |+N5-Y\x12:-1\r'


def obf(s: bytes):
    m = b'9NKLJCxPZikUXXgbTOVU'
    return bytes(c ^ m[i % len(m)] for i, c in enumerate(s))


class Tracker(object):
    """ Organize file structure and keep the archive clean. 
    
    Instances of this class organize where to place what files based on the given folder 
    structure and keep track of the seen files to simplify cleanup unused files afterwards. 
    """

    def __init__(self, path: str):
        """ Create enw tracker instance. 
        
        :param path: Path to the archive.
        """
        self.index = []
        self.path = path
        for dir_path, dir_names, file_names in os.walk(path):
            for name in dir_names + file_names:
                self.index.append(unicodedata.normalize('NFC', os.path.join(dir_path, name)))

    def cleanup(self):
        """ Remove all files in archive that where not requested since initialization. """
        for path in sorted(self.index, reverse=True, key=len):
            if os.path.isfile(path):
                try:
                    os.unlink(str(path))
                    logging.debug('removed file %r', path)
                except OSError:
                    pass
            elif os.path.isdir:
                try:
                    if not os.listdir(str(path)):
                        os.rmdir(str(path))
                        logging.debug('removed folder %r', path)
                except OSError:
                    pass

    def used(self, path: str):
        """ Mark a file as seen by it's absolute path. 
        
        :param path: Absolute path to the file to mark as seen.
        """
        normalized_path = unicodedata.normalize('NFC', path)
        if normalized_path in self.index:
            self.index.remove(normalized_path)
            return True
        else:
            return False

    @contextmanager
    def file_handler(self, folders: list, file_name: str):
        """ Get a file handler to store a new file.
                
        :param folders: List of path elements to store the file at.
        :param file_name: Name of the file to store        
        :rtype: Union[None, File]
        :return: None if the file already exists or a file handler.
        """

        if folders:
            file_dir = os.path.join(*folders)
        else:
            file_dir = ''

        if not self.used(file_dir):
            try:
                absolute_dir = os.path.join(self.path, file_dir)
                os.makedirs(absolute_dir)
                logging.debug('created folder %r', absolute_dir)
            except FileExistsError:
                pass

        absolute_path = os.path.join(self.path, file_dir, file_name)
        if not self.used(absolute_path):
            with open(absolute_path, 'wb') as fd:
                logging.debug('created file %r', absolute_path)
                yield fd
        else:
            yield None


def paper_documents(dbx: dropbox.Dropbox, page_size=1000):
    """ Get all dropbox paper document ids in this account.
    
    :param dbx: Dropbox instance with logged in account with sufficient permissions to list documents.
    :param page_size: Number of document ids to to get with one request.
    :return: Dropbox Paper ids.  
    """
    listing = dbx.paper_docs_list(limit=page_size)
    while True:
        for document_id in listing.doc_ids:
            yield document_id
        if listing.has_more:
            listing = dbx.paper_docs_list_continue(listing.cursor.value)
        else:
            break


def download_resource_file(url: str, fd: io.TextIOWrapper):
    """ Download a file. 
    
    :param url: The url to get the file from.
    :param fd: The file descriptor to write the file to.    
    """
    response = requests.get(url, stream=True, verify=False)
    for chunk in response.iter_content(chunk_size=2 ** 10):
        fd.write(chunk)


def replace_images(tracker: Tracker, folders: list, document_reference: str, body: bytes):
    """ Find all image references, download them and replace the references to the downloaded copies. 
    
    :param tracker: Instance of the tracker to create new files with.
    :param folders: List of folder names where the document is stored.
    :param document_reference: A string unique to the document.
    :param body: The documents body to search in.
    :return: The document body with replaced image references.
    """

    pattern = re.compile(rb'(<img[^<]+src=)(?P<delimiter>[\'"])(?P<url>[^\'"]+)(?P=delimiter)([^>]*>)')
    relative_resource_dir = '.%s' % document_reference
    cache = {}

    for index, match in enumerate(pattern.finditer(body)):
        begin, delimiter, url, end = match.groups()

        if url in cache:
            body = body.replace(match.group(0), begin + delimiter + cache[url].encode('utf-8') + delimiter + end)

        else:

            file_name = ("%d_" % index) + urllib.parse.urlparse(url).path.split(b'/')[-1].decode('utf-8')
            relative_url = os.path.join(relative_resource_dir, file_name)
            body = body.replace(match.group(0), begin + delimiter + relative_url.encode('utf-8') + delimiter + end)
            cache[url] = relative_url

            with tracker.file_handler(folders + [relative_resource_dir], file_name) as fd:
                if fd:
                    download_resource_file(url.decode('utf-8'), fd)

    return body


def store_document(export_format: str, tracker: Tracker, dbx: dropbox.Dropbox, document_id: str):
    """ Download a document to the local file system. 
    
    :param export_format: The format to store the document in. Possible values are "html", "markdown" 
        or "all". For "html" also referenced images are downloaded.
    :param tracker: Instance of the tracker to create new files with.
    :param dbx: Dropbox instance with logged in account with sufficient permissions to download documents.
    :param document_id: The document id if the paper document to download.    
    """

    try:
        folders = [folder.name for folder in dbx.paper_docs_get_folder_info(document_id).folders or []]
    except dropbox.exceptions.ApiError:
        folders = []

    if export_format == 'html' or export_format == 'all':
        document_meta, document_body = dbx.paper_docs_download(document_id, dropbox.paper.ExportFormat('html'))
        document_reference = "%s-%s" % (document_id, document_meta.revision)
        content = replace_images(tracker, folders, document_reference, document_body.content)
        file_name = "%s [%s].html" % (document_meta.title, document_reference)
        with tracker.file_handler(folders, file_name) as fd:
            if fd:
                fd.write(content)

    if export_format == 'markdown' or export_format == 'all':
        document_meta, document_body = dbx.paper_docs_download(document_id, dropbox.paper.ExportFormat('markdown'))
        document_reference = "%s-%s" % (document_id, document_meta.revision)
        content = document_body.content
        file_name = "%s [%s].md" % (document_meta.title, document_reference)
        with tracker.file_handler(folders, file_name) as fd:
            if fd:
                fd.write(content)


def backup(token: str, target: str, export_format='all'):
    """ Download all accessed documents in the dropbox account. 
    
    :param token: Token to login to the dropbox account.
    :param target: Relative or absolute path to the download target.
    :param export_format: he format to store the document in.
    """

    dbx = dropbox.Dropbox(token)
    tracker = Tracker(os.path.abspath(target))

    for index, document_id in enumerate(paper_documents(dbx)):
        try:
            store_document(export_format, tracker, dbx, document_id)
        except dropbox.exceptions.ApiError as e:
            logging.exception('dropbox api error for document %s: %s', document_id, e)

    tracker.cleanup()


def get_token():
    """ Request a new token to acces an dropbox account. """

    auth_flow = dropbox.DropboxOAuth2FlowNoRedirect(APP_KEY, obf(APP_SECRET).decode('ascii'))
    auth_url = auth_flow.start()
    webbrowser.open(auth_url)

    print("1. Go to: %s" % auth_url)
    print("2. Click \"Allow\" (you might have to log in first).")
    print("3. Copy the authorization code.")
    auth_code = input("Enter the authorization code here: ").strip()
    # noinspection PyBroadException

    try:
        oauth_result = auth_flow.finish(auth_code)
    except Exception:
        logging.exception("Receiving token failed.")
    else:
        print("Token received. From now on please start this script with:")
        print("  --token=%s" % oauth_result.access_token)


if __name__ == '__main__':

    sys.excepthook = lambda c, e, t: logging.critical('%s: %s\n%s', c, e, ''.join(traceback.format_tb(t)))
    arguments = docopt.docopt(__doc__.format(cmd=__file__))
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("dropbox").setLevel(logging.WARNING)
    logging.basicConfig(
        filename=arguments['--logfile'],
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        level=logging.DEBUG if arguments['--verbose'] else logging.INFO)

    if arguments['--token']:
        if arguments['markdown']:
            backup(token=arguments['--token'], target=arguments['<target>'], export_format='html')
        elif arguments['html']:
            backup(token=arguments['--token'], target=arguments['<target>'], export_format='markdown')
        else:
            backup(token=arguments['--token'], target=arguments['<target>'])
    else:
        get_token()
