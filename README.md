# Usage #
$ python3 JG_spd.py

Follow the instructions in the terminal and select one of the following options
1. encrypt a file
2. decrypt a file
3. remove a file
4. dump the log message
5. exit

# Program Description #
This program is a simple example of the functionality of self-protecting data. As this program is supplemented by a full writeup, I will save some details and further discussion for that document and provide a program description, explanation of functionality, and some reflection here.

## Self-Protecting Data Background ##
Self-protecting data is a recent revelation in the security industry focused on maintaining the security of sensitive files throughtout the full lifecycle of the data. SPD represents a move away from a responsive defense strategy to one that more proactively secures the underlying data. For example, instead of simply encrypting the data, a useful but less flexible defense measure, SPD can encompass a full suite of features via a protection policy. Some examples include:

- location detection
- governance data
- different levels of clearance (different users see different data or more/less data)
- self-destruction
- time-limited access
- etc

Clearly SPD is a more complex but much more flexible solution to protecting data over multiple hops, and different innovative platforms have been introduced to tackle this new problem, which are discussed at more length in the full writeup.

## Example Program Functionality ##
This programs serves as a proof of concept and displays knowledge of how a self-protecting data platform could function, albeit with less functionality and more limited security than a full-fledged consumer product. The basic structure and functionality is as follows:

- Run the program as shown in the usage section above
    - The terminal will first ask for a key which functions as the encryption key and adds a password- protected nature to the data, ideally communicated out of band.
    - Then the terminal will display a number of options
- First, a user will likely want to encrypt a file with option 1
    - After typing '1' and hitting enter, the program will ask the user to set the policy for the encrypted file. This is necessary at this point so the policy data can be packaged into the encrypted file and accessed accordingly on an attempt to decrypt. Leaving options blank will use the default value. The options are (in order):
        - Which plaintext file to encrypt (required)
        - Choose a name for the encrypted file, defaults to adding '.enc'
        - Choose an anchor point for the file such as 'NYC' or '1 Brookings Dr, St. Louis, MO 63130'
            - This point establishes a location that the decrypting machine must be in close proximity to in order to decrypt (see next option). Defaults to the location of the IP of the machine or the local ISP
        - Choose a distance in miles from the anchor point that a decryption attempt should be allowed to decrypt successfully, default 50 miles
        - Choose a time in seconds after which the decrypted file will be deleted, default 60 seconds
            - This works via spawning a new thread. The file is also deleted on program exit if it has not yet been deleted
        - Choose whether or not the file should self-destruct on a failed decryption attempt, another version of the encrypted file can always be sent if the key is mistyped

- Now that the file is encrypted with a corresponding protection policy, the user can immediately decrypt the file with option 2 to verify correct decryption
- Additionally, now the encrypted file is ready to be shared. The file can be sent over a medium like email. or simply exit the program and restart it to replicate the same behavior on the same machine
    - The intended recipient (or the same user in a newly started program) will repeat the first steps from above, inputting the correct key
    - Now input the path to the encrypted file and give a name for the decrypted file, defaults to adding '.dec'   
    - **If successful, both the encrypted and decrypted files will be avialable and a message showing success will print. (The decrypted message will delete itself after the set amount of time)**
    - **In an unsuccessful case, a message will indicate failure, no decrypted file will exist, and the encrypted file may self-destruct depending on the protection policy**
    - **Also note that any decrypted files will be deleted on program exit as an added security measure**

- The program also allows for deleting files, showing activity logs for the current session, and exitting the program (options 3, 4, and 5), all of which are relatively straightforward


## Shortcomings and Potential Future Improvements ##
Lastly, as this program is an example put together in a compressed timeframe, there are some shortcomings that are at least of note:
- The policy packing method may not be the most secure. Other implementations use a nested encryption strategy so all data in decrypted one piece of the policy at a time until finally the underlying data
- The geolocation is imperfect and uses Python libraries that may be easily skirted with a proxy or another similar strategy
- Key passing could prove an issue, one that threatens to remove security altogether for the sake of convenience if the keys are publicized or used widely

### Improvements and Wish List ###
- Improve policy packing security to avoid malicious actors discovering anchor point and other sensitive policy data
- Allow a full suite of defaults to be established for the entire company or even a subset of related files
- Establish improved key management and utilize multiple keys (PKI)
- Add user clearance levels to allow different amounts of data to be decrypted based on the user
- Potentially utilize check-in server to verify location and authentication more concretely
- More closely mirror actual implementation with each SPD object as a filesystem instead of a file
- Send logs back to server/owner on exit
- Improve error detection and maintain more secure hold of decrypted data

# Program Logs #
The operation record and HMAC is stored in ./op_trace.txt   
The cp record during the data processing and HMAC is stored in ./op_monitor.txt

Option 4 allows the user to see logs of the current session, logs are also printed before program exit