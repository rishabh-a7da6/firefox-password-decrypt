import csv
import json
from firefox import *

if __name__ == '__main__':
    try :
        with open('passwords.csv', mode='w', newline='', encoding='utf-8') as decrypted_file:
            writer = csv.writer(decrypted_file, delimiter=',')

            # Writing Header row in CSV File
            writer.writerow(["Profile", "Access_URL", "Username", "password"])

            # Getting list of all Profiles
            allProfiles = getAllProfiles(FIREFOX_PATH)

            for profile in allProfiles:
                try:
                    with open(profile) as f:
                        data = json.load(f)

                        try:
                            logins = data["logins"]
                        except Exception as e:
                            print(e)

                    # loading nss library
                    nss = locateAndLoadNss()

                    for login in logins:
                        username = login['encryptedUsername']
                        password = login['encryptedPassword']
                        hostname = login['hostname']

                        decryptedUsername = decrypt(profile, username, nss)
                        decryptedPassword = decrypt(profile, password, nss)

                        writer.writerow([os.path.basename(os.path.dirname(profile)), hostname, decryptedUsername, decryptedPassword])

                except Exception as e:
                    pass

    except Exception as e:
        print(e)