import subprocess
import re
import os




#globals
########
strIpPattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'  # Regular expression pattern for matching an IP address
aErrors = {}



#config section
###############

strLogExtract = "/opt/fail2ban-xrdp/xrdp-log.sh"		#script which extract the xrdp-log
strBlockScript = "/opt/fail2ban-xrdp/xrdp-block.sh "	#script which blocks an IP


#add ip's that shoudln't be blocked here
aAllowList = ['127.0.0.1', 'example']

#key sentences in the log, idicating someone trying to
#attack xrdp
aBadSentence = ['header read error',
                'Connect-Initial failed',
                'receive connection request failed',
                'trans_write_copy_s failed',
                'DisconnectProviderUltimatum failed',
                'Authentication failure']






result = subprocess.run([strLogExtract, ""], shell=True, capture_output=True, text=True)
lines = result.stdout.split("\n")

bHaveIP = False
bHaveErr = False
strIP = ""

for line in lines:
    if "xrdp" in line:
        #check for incoming connections
        if "connection received from" in line:
            matches = re.findall(strIpPattern, line)
            
            if len(matches) > 0:
                strIP = str(matches[0])
                
                bAllowed = False
                        
                for wl in aAllowList:
                    if strIP == wl:
                        bAllowed = True
                        
                if bAllowed  == False:
                    
                    bHaveIP = True
                    bHaveErr = False
                
                else:
                    print(strIP, "is in allow list, ignore...")
                    strIP = ""
            
        else:
            #if we have a connection, search for bad things
            if bHaveIP == True and bHaveErr == False:
                for strErr in aBadSentence:
                    if strErr in line:

                        if strIP in aErrors:
                            aErrors[strIP] = ({"ErrCount": aErrors[strIP].get("ErrCount") + 1})
                        else:
                            aErrors[strIP] = ({"ErrCount": 1})
                          
                        #reset, next ip
                        bHaveIP = False
                        bHaveErr = True
                        strIP = ""
                        
                        break;
         
     
if len(aErrors) > 0:
    for key in aErrors:
        
        if aErrors[key].get("ErrCount") > 2:
            
            print("Block", key, "Error count: ", aErrors[key].get("ErrCount"))
            
            strCommand = strBlockScript + key
            os.system(strCommand)
            
else:
    print("No IP's to block")
            
#print(output)



