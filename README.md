# Dropbox Paper Backup

Download all documents from an Dropbox-Paper account to a local path.

While its very easy to download and maintain a complete copy of your complete Dropbox with tools like [rclone](http://rclone.org/), it's hard to have backups of the documents created in [Dropbox Paper](paper.dropbox.com).

For this reason i wrote this little script to run periodically on my NAS.


# Usage:

    ./dropbox-paper-backup.py [--token=TOKEN] [--logfile=PATH] [--verbose] [markdown|html] <target>

    Options:
      -t --token=TOKEN    The access token for the dropbox account. Omit to get a new token.
      -l --logfile=PATH   Log to the specified file.
      -v --verbose        Be more verbose.
      markdown|html       Export either as "html" or as "markdown". Do both if omitted.
      <target>            The path to store the backup in.


# Installation

1. Get the script and setup permissions:

    git clone https://github.com/efenka/dropbox-paper-backup.git
    cd dropbox-paper-backup
    chmod u+x dropbox-paper-backup.py

2. Install dependencies:

    pip3 install -r requirements.txt

3. Create a backup destination and request a authorisation token:

    ./dropbox-paper-backup.py ./archive

4. Run the script again, giving the token returned by the previous step.

    ./dropbox-paper-backup.py --token=TOKEN ./archive

Depended on how many files you have, it may take a while.
