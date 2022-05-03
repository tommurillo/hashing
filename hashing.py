#!/usr/bin/env python3
import hashlib

def scan(dict_file, hash):
  f = open(dict_file, 'r')
  list1 = f.readlines()
  f.close()

  #print(list1)
  #print (hashlib.algorithms_available)
  #hash_default_algorithm = "md5"

  hash_alg_avail = {}
  for x, e in enumerate(hashlib.algorithms_available):
    print (str(x) +":"+ str(e))
    hash_alg_avail.update({str(x):str(e)})
    
  print("Select which hash algorithm or blank for auto")
  selected_hash_alg = input()

  #print(hash_alg_avail)
  hash_len_max = len(hash_alg_avail)
  if selected_hash_alg == "":
    selected_hash_alg = "Auto"
  elif int(selected_hash_alg) > hash_len_max:
    while int(selected_hash_alg) > hash_len_max:
      print("Out of bound! Select new one.")
      selected_hash_alg = input()

  if selected_hash_alg != "Auto":
      selected_hash_alg = hash_alg_avail.get(selected_hash_alg)

  #print("Selected: " + repr(selected_hash_alg))
  print("Selected hash algorithm: " + selected_hash_alg)

  if selected_hash_alg == "Auto":
    list_hash_alg = list(hash_alg_avail.values())
  else:
    list_hash_alg = selected_hash_alg.split("\n")

  #print(list_hash_alg)

  for current_hash_alg in list_hash_alg:
    for x in list1:
      x = x.strip("\n")
      
      #hash_object = hashlib.new(selected_hash_alg)
      hash_object = hashlib.new(current_hash_alg)
      hash_object.update(x.encode())
      if current_hash_alg != "shake_128" and current_hash_alg != "shake_256":
        hash_object = hash_object.hexdigest()
      
      #print(str(current_hash_alg)+":"+repr(x)+":"+str(hash_object))
      #print(str(x) +":"+ str(hash_object))
      if str(hash_object) == str(hash):
        return "Under " + current_hash_alg +": Found a match! The password is: " + x

    print("Under " + current_hash_alg +": No password found")
        
def main():
  dict_file = "./dictionary.txt"
  desired_hash = "1a79a4d60de6718e8e5b326e338ae533"
  #desired_hash = "865c5ea37234f2b945f1cf78c79e84ede253dac29b22f87149d63323dc08cd7de9ea13964ccf83199b6d4ed102a4cbec87b9c93f2f917fd433d9e54a7cce4c59"
  print(scan(dict_file, desired_hash))
  
main()
