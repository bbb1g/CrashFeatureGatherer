#/usr/bin/python

from glob import glob
import os
import shutil

#a = glob("/home/bbbig/capstone/work/CGC/*/out/master/crashes/*")
HOME = "/home/bbbig/capstone"

def set_init_env():
  '''Make Result Directory'''

  if not os.path.exists(HOME + "/res"):
    os.mkdir(HOME + "/res")

  # Make sure crash make core file
  # $ulimit -c unlimited

def exec_binary(binary):
  os.system("timeout 3 %s < ./input"%binary)

def make_core(binary, crash_id):
  pass

def get_crash_id(crash_name):
  return int(crash_name.split("id:")[1].split(",")[0])

def get_crash_exists_binary():
  '''Make core files from crash input'''

  out_folders = glob(HOME + "/work/CGC/*")
  crash_exists = []

  for out_folder in out_folders:
    crash_folder = os.path.join(out_folder, "out/master/crashes")
    crashes = glob(os.path.join(crash_folder, "*"))

    if len(crashes) == 0:
      continue

    crash_exists.append(out_folder)
      
  return crash_exists

def make_core_for_all():

  res_folder = os.path.join(HOME, 'res')
  crash_exists = get_crash_exists_binary()

  for crash_exist in crash_exists:
    bin_name = os.path.basename(crash_exist)
    bin_path = os.path.join(HOME, 'target/CGC/'+bin_name)
    print bin_path
    crashes = glob(os.path.join(crash_exist, "out/master/crashes/*"))
    for crash in crashes:

      if not os.path.basename(crash).startswith("id"):
        continue

      bin_folder = os.path.join(res_folder, os.path.basename(crash_exist)) 
      if not os.path.exists(bin_folder):
        os.mkdir(bin_folder)

      crash_id = get_crash_id(crash)
      crash_folder = os.path.join(bin_folder, 'crash%d'%crash_id)

      if not os.path.exists(crash_folder):
        os.mkdir(crash_folder)
      
      os.chdir(crash_folder)
      shutil.copyfile(crash, 'input')
      shutil.copyfile(bin_path, '../' + bin_name)

      exec_binary(bin_path)

if __name__ == "__main__":
  set_init_env()
  make_core_for_all()
