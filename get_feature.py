#!/usr/bin/python

from glob import glob
import os
from pwn import process, context, log

HOME = '/home/bbbig/capstone'
context.log_level = 'error'

class FeatureGetter(object):

  def __init__(self, bin_path, core_path):

    self.bin_path = bin_path
    self.core_path = core_path
    gdb_cmd = 'gdb -q %s %s'%(bin_path, core_path)
    self.gdb = process(gdb_cmd.split(' '))
    self.features = [0]*44


  def gdb_delim(self):
    return self.gdb.recvuntil('(gdb) ')

  def get_info_from_gdb(self):
    pass

  def parse_maps(self):

    maps = []

    os.system('readelf --segments %s > /tmp/segment'%core_path)

    for line in open('/tmp/segment'):
      if not 'LOAD' in line:
        continue

      pos = line.split('           ')[1]
      pos = pos.split(' ',1)[1]
      addr, pos = pos.split(' ',1)
      addr = int(addr, 16)

      pos = pos.split(' ',1)[1]
      pos = pos.split(' ',1)[1]
      size, pos = pos.split(' ',1)
      size = int(size, 16)

      perm = list(pos[:3])
      
      for _ in range(3):
        if perm[_] == ' ':
          perm[_] = 0
        else:
          perm[_] = 1

      maps.append([addr, size, perm])
    
    return maps


  def parse_stack_frame(self):

    addrs = []
    self.gdb.sendline('bt 10')
    out = self.gdb_delim()

    for line in out.split('\n'):
      if not line.startswith('#'):
        continue

      try:
        addr = line.split('0x')[1].split(' ')[0].strip()
        addr = int(addr, 16)
        addrs.append(addr)
      except:
        pass

    return addrs

  def parse_registers(self):
    
    regs = {}
    self.gdb.sendline('i r')
    out = self.gdb_delim()

    for line in out.split('\n')[:-1]:
      name = line[:6].strip()
      val = int(line[15:].split('\t')[0],16)
      regs[name] = val

    return regs


  def parse_signo(self):
    
    self.gdb.sendline('p $_siginfo')
    out = self.gdb_delim()

    signo = int(out.split('si_signo = ')[1].split(',')[0])

    return signo


  def parse_instruction(self):

    self.is_bad_inst = 0
    self.operator = ''
    self.operand = ''
    self.num_of_operand = 0

    self.gdb.sendline("x/i $eip")
    out = self.gdb_delim()
    inst = out.split('\n')[0]

    if 'bad' in inst:
      self.is_bad_inst = 1
    else:
      pos = inst.split(":")[1].lstrip()
      if len(pos) < 3:
        pos = out.split('\n')[1].lstrip()
      #print inst
      self.operator = pos[:7].strip()
      self.operand = pos[7:]

      if len(self.operand) < 2:
        self.num_of_operand = 0
      else:  
        self.num_of_operand = len(self.operand.split(','))


  def check_addr_valid(self, addr, perm):

    valid = 0

    for seg_start, seg_size, seg_perm in self.maps:

      if addr >= seg_start and addr < seg_start + seg_size:
        nope = 0

        for perm_idx in range(3):
          if perm[perm_idx]:
            if not seg_perm[perm_idx]:
              nope = 1
              break
        
        if not nope:
          valid = 1
          break

    return valid


  def get_addr_segment(self, addr):

    for seg_start, seg_size, seg_perm in self.maps:
      if addr >= seg_start and addr < seg_start + seg_size:
        return [seg_start, seg_size, seg_perm]

    return None


  def is_branch_inst(self):
    
    op = self.operator

    if 'ret' in op or 'call' in op or 'j' in op:
      return 1

    return 0

  
  def parse_flags(self):

    flag = self.regs['eflags']

    CF = flag & 1
    PF = (flag >> 2) & 1
    AF = (flag >> 4) & 1
    ZF = (flag >> 6) & 1
    SF = (flag >> 7) & 1
    TF = (flag >> 8) & 1
    IF = (flag >> 9) & 1
    DF = (flag >> 10) & 1
    OF = (flag >> 11) & 1
    IO_PL = (flag >> 12) & 1
    NF = (flag >> 14) & 1
    RF = (flag >> 16) & 1
    VM = (flag >> 17) & 1
    AC = (flag >> 18) & 1
    VIF = (flag >> 19) & 1
    VIP = (flag >> 20) & 1
    ID = (flag >> 21) & 1

    return [CF,PF,AF,ZF,SF,TF,IF,DF,OF,IO_PL,NF,RF,VM,AC,VIF,VIP,ID]


  
  def set_feature_idx(self):
    '''
    Feature Index Table
    0 : Backtrace corrupt?
    1 : EIP addr valid?
    2 : EBP addr valid?
    3 : ESP addr valid?
    4 : operator valid?
    5 : EIP addr seg R?
    6 : EIP addr seg W?
    7 : EIP addr seg X?
    8 : EIP addr seg WE?
    9 : mem operand addr valid?
    10 : mem operand src?
    11 : mem operand dest?
    12 : mem operand null?
    13 : num_of operand 0?
    14 : num_of operand 1?
    15 : num_of operand 2?
    16 : num_of operand 3+?
    17 : operand memory?
    18 : operand immediate?
    19 : operand reg?
    20 : operand real num?
    21 : branch inst?
    22 ~ 38 : flags
    39 ~ 43 : signals
    '''

    eip_addr = self.regs['eip']
    ebp_addr = self.regs['ebp']
    esp_addr = self.regs['esp']

    eip_seg = self.get_addr_segment(eip_addr)


    #feature 1:
    self.features[1] = self.check_addr_valid(eip_addr, [1,0,1])

    #feature 2:
    self.features[2] = self.check_addr_valid(ebp_addr, [1,1,0])

    #feature 3:
    self.features[3] = self.check_addr_valid(esp_addr, [1,1,0])

    #feature 4:
    self.features[4] = not self.is_bad_inst

    #feature 5:
    self.features[5] = eip_seg[2][0]

    #feature 6:
    self.features[6] = eip_seg[2][1]

    #feature 7:
    self.features[7] = eip_seg[2][2]

    #feature 8:
    self.features[8] = eip_seg[2][1] and eip_seg[2][2]

    

    #feature 13:
    self.features[13] = self.num_of_operand == 0

    #feature 14:
    self.features[14] = self.num_of_operand == 1

    #feature 15:
    self.features[15] = self.num_of_operand == 2

    #feature 16:
    self.features[16] = self.num_of_operand >= 3

    #feature 17:
    self.features[17] = '(' in self.operand or ')' in self.operand

    #feature 18:
    self.features[18] = '$' in self.operand

    #feature 19:
    self.features[19] = '%' in self.operand

    #feature 20:
    if self.operator:
      self.features[20] = self.operator.startswith('f')
    else:
      self.features[20] = 0

    #feature 21:
    self.features[21] = self.is_branch_inst()


    # Feature idx 22 ~ 38:
    flags = self.parse_flags()
    for idx in range(17):
      self.features[22 + idx] = flags[idx]


    # Feature idx 39 ~ 43:
    signo = self.signo
    self.features[39] = signo == 10 or signo == 9 or signo == 12 or signo == 15
    self.features[40] = signo == 4  # Illegal Instruction
    self.features[41] = signo == 11 # Segmentation Fault
    self.features[42] = signo == 8  # Floating
    self.features[43] = signo == 6  # Abort

    for _ in range(len(self.features)):
      self.features[_] = int(self.features[_])

  def start(self):
 
    self.gdb_delim()
    self.gdb.sendline("set print symbol off")
    self.gdb_delim()

    self.maps = self.parse_maps()
    self.stack_frame = self.parse_stack_frame()
    self.regs = self.parse_registers()
    self.signo = self.parse_signo()
    self.parse_instruction()
    self.set_feature_idx()
    
    '''
    print 'Maps : ', self.maps
    print 'Stack Frame : ', self.stack_frame
    print 'Regs : ', self.regs
    print 'Sigal Number : ', self.signo
    print self.operator
    print self.operand
    print self.num_of_operand
    print self.features
    '''

    self.gdb.close()

if __name__ == '__main__':
  
  res_dir = os.path.join(HOME, 'res')
  target_bins = glob(res_dir + '/*')
  
  for bin_folder in target_bins:
    f_ls = glob(bin_folder + '/*')

    for idx in xrange(len(f_ls)):
      if os.path.isfile(f_ls[idx]):
        bin_path = f_ls.pop(idx)
        break

    for crash_f in f_ls:
      core_path = os.path.join(crash_f, 'core')

      if not os.path.exists(core_path):
        os.remove(os.path.join(crash_f, 'input'))
        os.rmdir(crash_f)
        continue

      print '[+] parsing',
      print os.path.basename(bin_path),
      print core_path.split('/')[-2]

      fg = FeatureGetter(bin_path, core_path)
      fg.start()
      print fg.features
