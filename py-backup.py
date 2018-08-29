#!/usr/bin/python3.6 -W ignore

import peewee
import hashlib
import logging
import os
import pickle
import datetime
import shutil
import argparse
from pretty_bad_protocol import gnupg
from socket import gethostname

parser = argparse.ArgumentParser()
parser.add_argument("folder", help="Folder to back up.")

args = parser.parse_args()

db = peewee.MySQLDatabase("dbname", host="dbhost", user="dbuser", passwd="dbpassword")

gpg = gnupg.GPG(homedir='/root/.gnupg')
gpg.binary = '/usr/bin/gpg2'

backupmount = "/landing/folder/for/data"
tempfolder = "/folder/for/temp/data"
backupdir = datetime.datetime.now().strftime('%Y/%m/%d')
backupdest = os.path.join(backupmount, backupdir)
recipient = "gpg@recipient"

class BackUpData(peewee.Model):
  o_sha256 = peewee.CharField()
  e_sha256 = peewee.CharField(default="")
  filename = peewee.CharField()
  filepath = peewee.CharField(max_length=1024)
  filestat = peewee.BlobField(default="")
  backupdir = peewee.CharField()
  host = peewee.CharField()
  mtime = peewee.IntegerField()
  isbackedup = peewee.BooleanField(default=False)
  class Meta:
    database = db

# https://stackoverflow.com/a/3431838
def sha256(fname):
  hash_sha256 = hashlib.sha256()
  with open(fname, "rb") as f:
    for chunk in iter(lambda: f.read(4096), b""):
      hash_sha256.update(chunk)
  return hash_sha256.hexdigest()

def enoughFreeSpace(sourcefile, destdir):
  if os.stat(sourcefile).st_size < int(shutil.disk_usage(destdir).free):
    return True
  else:
    return False

def checkCreateFolder(folder):
  if not os.path.exists(folder):
    try:
      os.makedirs(folder)
    except Exception as e:
      print(e)

def scantree(path):
  for entry in os.scandir(path):
    if entry.is_dir(follow_symlinks=False):
      yield from scantree(entry.path)
    else:
      yield entry

def getsig(recipient):
  for sigs in gpg.list_sigs():
    for uids in sigs['uids']:
      if recipient in uids:
        return sigs

def encryptFile(filelocation, keyid):
  checkCreateFolder(tempfolder)
  if not enoughFreeSpace(filelocation, tempfolder):
    raise Exception("Not enough free space in temp location: {}".format(tempfolder))
  try:
    with open(filelocation, 'rb') as infile:
      status = gpg.encrypt(infile, keyid, output=os.path.join(tempfolder, os.path.basename(filelocation)))
    efname = sha256(os.path.join(tempfolder, os.path.basename(filelocation)))
    os.rename(os.path.join(tempfolder, os.path.basename(filelocation)), os.path.join(tempfolder, efname))
    return(os.path.join(tempfolder, efname))
  except Exception as e:
    print("File encryption exception: {}".format(e))

def archiveFile(filelocation, filedestination):
  if not enoughFreeSpace(filelocation, os.path.dirname(filedestination)):
    raise Exception("Not enough free space in destination: {}".format(os.path.dirname(filedestination)))
  if not os.path.isfile(filedestination):
    while True:
      try:
        shutil.move(filelocation, filedestination)
        print("-- success")
      except Exception as e:
        print("-- failed: {}".format(e))
        continue
      break

checkCreateFolder(backupdest)
sig = getsig(recipient)
for entry in scantree(args.folder):
  try:
    bd = BackUpData.select().where((BackUpData.filepath==entry.path) & (BackUpData.mtime==int(entry.stat().st_mtime)) & (BackUpData.isbackedup == True)).get()
#    print("Already archived {}".format(entry.path))
  except BackUpData.DoesNotExist:
    try:
      bd = BackUpData.select().where((BackUpData.filepath==entry.path) & (BackUpData.mtime==int(entry.stat().st_mtime))).get()
    except BackUpData.DoesNotExist:
      bd = BackUpData.create(o_sha256=sha256(entry.path), filename=entry.name, filepath=entry.path, filestat=pickle.dumps(entry.stat()), backupdir=backupdir, host=gethostname(), mtime=int(entry.stat().st_mtime))
    print("Backing up {} ".format(entry.path), end='')
    efilepath = encryptFile(entry.path, sig['keyid'])
    bd.e_sha256 = sha256(efilepath)
    bd.save()
    try:
      archiveFile(efilepath, os.path.join(backupdest, os.path.basename(efilepath)))
      bd.isbackedup = True
      bd.save()
    except Exception as e:
      print("File archive exception: {}".format(e))
