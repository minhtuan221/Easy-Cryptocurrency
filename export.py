from distutils.dir_util import copy_tree
import os


# Get current dir
fromDirectory = os.getcwd()
# get current dir name
foldername = os.path.basename(fromDirectory)

# copy subdirectory example
# combine current dir with go-path
toDirectory = "/Users/minhtuannguyen/go/src/"+foldername

# Get all subdir abs path
from glob import glob
listdir = glob("./*/")
print(listdir)
for folder in listdir:
    copy_tree(fromDirectory + folder[1:-1], toDirectory+folder[1:-1])

# d = '.'
# listFolder = [os.path.join(d, o) for o in os.listdir(d) if os.path.isdir(os.path.join(d, o))]
# print(listFolder)
