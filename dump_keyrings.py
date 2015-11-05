#
# Dumps all keys stored in Ubuntu keyrings
#

import gnomekeyring
 
def extract_keys():
    ''' Extract the usernames and passwords from all the keyrings'''
    
    for keyring in gnomekeyring.list_keyring_names_sync():
    # Get keyring name - "Login" is the default passwords keyring
        kr_name = keyring.title()
        print "Extracting keys from \"%s\" keyring:" % (kr_name)
        
        items = gnomekeyring.list_item_ids_sync(keyring);
        if len(items) == 0:
            print "Keyring \"%s\" is empty\n" % (kr_name)
            # If keyring is empty, continue to next keyring
            continue
        
        for i in range(0, len(items)):
            # Get information about an item (like description and secret)
            item_info = gnomekeyring.item_get_info_sync(keyring, items[i])
            description = item_info.get_display_name()
            password = item_info.get_secret()

            # Get attributes of an item (retrieve username)
            item_attr = gnomekeyring.item_get_attributes_sync(keyring, items[i])
            username = item_attr['username_value']

            print "[%d] %s" % (i, description)
            print " %s:%s" % (username, password)
        print ""
 
if __name__ == '__main__':
    extract_keys()
