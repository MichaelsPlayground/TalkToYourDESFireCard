# Manual to Talk to your DESFire EV3 card

This is a manual that describes how to work with this app. All methods described in the manual do 
work properly and are tested on a DESFire EV3 tag using the '2KB' version. 

## Note on material covered by a Non Disclosure Agreement (NDA)

Most of the methods are located in the DesfireEv3.java class and the development was done without any 
material that is covered by a Non Disclosure Agreement (NDA), because no full datasheet for DESFire EV1/2/3 was 
available at time of creating. Fortunately there are datasheets and accompanying documents available for other 
tags (e.g. DESFire Light and NTAG 424 DNA) and they provided the necessary information for the tasks. To make 
it short: there is NO BREACH OF ANY DISCLOSURE AGREEMENT.

## Does your app work with DESFire EV1 and EV2 tags as well ?

Most of the functionality described in this document is available within the DESFire EVx family and the app 
should work properly with these tags as well. But for read and write operations using communication modes MACed or 
Full enciphered the library is using the "**AuthenticateEV2First*" command available on DESFire EV2 and onwards only.

As I do not have DESFire EV1 or EV2 tags available I could not test the functionality and the answer is:

- for DESFire EV1 tags the read and write operations on files with Plain communication mode only should work, all others will fail
- for DESFire EV2 tags the full functionality should be available

## Which key and authentication does this app use ?

The sample application is based on **AES-128 keys**. As authentications methods the (old) **authenticateLegacy** method 
is available for unlocking read and write operations on files with communication mode "Plain". For files with 
communication modes "MACed" and "Full" enciphered the **AuthenticateEV2First** method is used. This app is 
NOT using any "Leakage Resilient Primitive" (LRP) methods.

## How do we start with a DESFire EV3 tag.

For a good user experience it is helpful to work with a brand new (empty) tag with **factory settings**. This is due to the 
fact that you can change some settings on the tag that prohibit a proper workflow. For example there is a setting 
available that the listing of applications and files is possible only after a preceding authentication. The app is not 
prepared for such a behaviour and will fail. Unfortunately these settings (done on the Master Application) are not 
getting reset after formatting the tag (only if you change the settings back to factory settings).

## Can I damage or brick my tag when using this app ?

To avoid any damage on the tag I left out all commands that may irrevocably sets values. As this app is working on 
**application level** only all settings are removed when formatting the tag (this will release the user memory and 
nothing of this app will remain on the tag).As far as I can overview the methods within this app there should be 
no risk on using this app but a general problem remains - all write commands can get disturbed (e.g. when moving the 
tag out of Android's NFC reader range) and can leave unwanted results or damage, sorry.  

## What are the steps to run the methods ?

This app is using the full spectrum of file operations available on a DESFire EV3 tag, meaning that you can read from and 
write to **Standard files**, **Backup files**, **Value files**, **Linear Record files** and **Cyclic Record files**. All 
communication modes (**Plain**, **MACed** and **Full enciphered**) are available as well with file (or record) sizes up 
to 256 bytes.

For easy usage of all file types there is a main menu option "**setup test environment**" available that will create the 
sample application containing all files types in all communication modes in one call; after processing there are 15 files 
created. 

After this setup you can proceed in the main menu.

## What files are created in setup test environment ?

**Warning: this activity will IMMEDIATELY format a tag when tapped to the Android's NFC reader without any further confirmation.
You will loose any existing applications and files on the PICC without recovery !** 

These steps will be run and 15 files got created:

1) The app will FORMAT the PICC so the complete PICC memory is available. The PICC will be formatted immediately after tapping without any further confirmation, the PICC is authenticated with DEFAULT DES Master Application KEY
2) The app will create a new application with **applicationID A1A2A3**. The app will have 5 **AES based application keys**.
3) There are no restrictions in application on file and directory handling (default settings).
4) In the new application files are created with these file numbers and access rights (R&W 1, CAR 2, R 3, W 4; see below):
       
- 00 Standard File, 256 file size, communication mode Plain
- 01 Standard File, 256 file size, communication mode MACed
- 02 Standard File, 256 file size, communication mode Full enciphered
- 03 Backup File, 32 file size, communication mode Plain
- 04 Backup File, 32 file size, communication mode MACed
- 05 Standard File, 32 file size, communication mode Full enciphered
- 06 Value File, communication mode Plain
- 07 Value File, communication mode MACed
- 08 Value File, communication mode Full enciphered
- 09 Linear Record file, 32 record size, 3 maximum number of records, communication mode Plain
- 10 Linear Record file, 32 record size, 3 maximum number of records, communication mode MACed
- 11 Linear Record file, 32 record size, 3 maximum number of records, communication mode Full enciphered
- 12 Cyclic Record file, 32 record size, 4 maximum number of records, communication mode Plain
- 13 Cyclic Record file, 32 record size, 4 maximum number of records, communication mode MACed
- 14 Cyclic Record file, 32 record size, 4 maximum number of records, communication mode Full enciphered

A short explanation on **Access rights**: each file gets it's individual access rights (can be changed later) 
and if you running a file operation you need to **authenticate** first or you receive an authentication error.

This are the 4 available access rights:
- R&W: **Read & Write Access Rights key**: after authentication with this key all read and/or write operations are permitted
- CAR: **Change Access Rights key**: for changing the authentication keys of a file a preceding authentication with this key is necessary
- R: **Read Access Rights key**: after authentication with this key all read operations are permitted
- W: **Write Access Rights key**: after authentication with this key all write operations are permitted

The key numbers need to be in the range of the number of keys setup during application setup. The sample application is setup 
with 5 keys - key number 0 ist the so called **Application Master key** that is necessary to enable some file creation methods.

There are additional "key numbers" available:
- key number "14" means **free access**, meaning you do need no preceding authentication before running the action
- key number "15" means **never access**, meaning you can't run any task coupled with this key (e.g. setting the Change Access 
Rights key to "15" will prohibit from any further access rights changing)

## What are the next steps after setting up the test environment ?

Using the menu you return to the main menu and tap the tag to the reader; the app will recognize the tag and provides the tag id ("UID") and 
the information that the app and the tag are ready to use.

As all files are located within an application you press the "select app" button (red background) and all applications on the tag are presented. After 
preparing the tag with "setup test environment" only one application is available and you should press on "A1A2A3" in the dialog window.

The "selected application" now shows the sample application ID and now you can select a file - press the "select file" button (red background).

All 15 created files are displayed within a dialog window; just press on the file you like to work with.

The "selected file id" now shows the file number, the file type and the communication mode of the file. 

For a short demonstration, select a Standard file in Full enciphered communication mode (file number 2), scroll down to the 
"authenticate with default of changed keys" section and press the button for "1 App R&W default" (green background). You will notice 
a short vibration indicating that the operation ended with success. Now the tag is unlocked to all read and write operations.

Next press the "write" button (orange background) above in the "Standard or Backup file section" and a vibrate is indicating success. 
Now press the "read" button (orange background) and the read content of the Standard file is shown in the "operation output" on top of the 
activity.

This is a typical output of the read task:

```plaintext
read from a data file fileNumber: 2 data length: 256 data: 323032332e30382e32372031303a33323a3533000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebec
read from a data file fileNumber: 2 data: 2023.08.27 10:32:53??!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~�������������������������������������������������������������������������������������������������������������
```

Note: all write operations on Standard, Backup, Linear Record and Cyclic Record files are writing a timestamp, followed by ascending byte 
values, to the file. This app does not support the writing of individual data to the files.  

For detailed information about the available file operations see the manual on desfire_ev3_file_operations.

There are some more methods available, see the  manual on desfire_ev3_more_operations.

A new feature on DESFire EV3 tags is the  **Transaction MAC file**, for more information on this see the desfire_ev3_transaction_mac_file_operations page.

## What commands are supported by the library ?

The library isn't supporting all commands, but all core commands are supported.

### Application section commands

As all files are located within an application the most used command is the **selectApplicationByAid**. THe seconds way of selecting is 
**selectApplicationByIsoDfName**. For tag exploring the library supports the **getApplicationIds** command.

### Data Files section commands

Two file types are covered by Data Files: **Standard Files** and **Backup Files**. As both work mostly identical they are condensed 
under Data Files. The library supports the **createDataFile** command. As a Data File can be setup in communication modes Plain, MACed or Full there 
are 3 different methods respectively for **readADataFile** and **writeADataFile**. Just a note on Backup files only: after firing the writeADataFile 
command you need to commit the transaction (see below).

### Value Files section commands

The library supports the **createValueFile** and the **readValueFile** commands. As we cannot directly write a new value the value is changed 
by the **creditValueFile** and **debitValueFile**. Just a note on Value files: after firing the credit- or debit value file 
command you need to commit the transaction (see below).

### Record Files section commands

Two file types are covered by Record Files: **Linear Record File** and **C<clic Record File**. The command handling is identical (just the 
behaviour of the file is different, see above) for **createRecordFile**, **writeToRecordFile** and **readARecordFile**. Just a note on Record 
files: after firing the write to a record file command you need to commit the transaction (see below).

### Several File section commands

For tag exploring the library supports the **getFileIds** and **getApplicationDfNames** commands. When an application is selected the library 
internally get all file ids and **getFileSettings** for all existing files. If you want to change some settings simply use the **changeFileSettings** 
command. The **deleteFile** is supported (please remember: the deletion of a file does not release the used memory of the file).

### Commit section commands

Write operations to a Backup-, Value-, Linear Record- or Cyclic Record file needs to get commit before they are written finally. You need to fire this 
command from (Main) activities side as the general workflow allows to send data to several files in the same application and commit all write operations 
in one commit command (**commitTransaction**). As there is an optional file type available (**Transaction MAC file**) there might be some extra steps 
to run before committing a transaction, see Transaction MAC file for details. The opposite command of a commitTransaction is the 
**abortTransaction** command that cancels all write operations done after an selectApplication or commitTransaction command.

### Transaction MAC File section commands

The Transaction MAC file (TMAC file) is a special feature available on DESFire EV2/EV3 and DESFire Light tags only. This file stores the last transactions 
on the tag so a backend server is been able to prove that all transactions had been processed correctly. The library does NOT support any 
methods to validate the data in this file but can request the return of the updated value after a successful COMMIT command.

There is an additional option during creation of a TMAC file - running a preceding **commitReaderId**. If this option is set a commitTransaction 
command will fail unless a previous commitReaderId command is fired. The TMAC file includes the reader Id in the calculation.

### Key commands

To receive the version of a key the **getKeyVersion** is supported. The change of the key value can be done by **changeApplicationKey**. To avoid 
any damage on the tag the library prohibits the change of keys on Master Application level.

### Authenticate section commands

The most important command is the **authentication**. The app is using two different authentication methods depending on the communication 
mode: when a file is in communication mode **Plain** the library is using the legacy **authenticateD40** method whereas when a file is in 
communication modes **MACed** or **Full enciphered** the app is using the modern **authenticateAesEv2First** or **authenticateAesEv2NonFirst** 
methods. The app is authenticating only on application level and with **AES-128 keys** only.

### General commands

On creation of new files you may encounter an "out of memory" error due to insufficient user memory on the tag. This happens very quickly when 
you create too large Data files, Record files with too many records or applications with a large number of application keys (each key gets part of the application memory usage). 
The **getFreeMemory** lets you find out how many bytes are available on the tag. As mentioned before, the deletion of files does not release 
the storage space. The only way to release the tag's memory is the  **formatPicc** command that comes with a confirmation dialog (available on 
UI level only, not on library level). This command runs after a successful authentication with the Master Application Key only.

An interesting command is the **getVersion** command. It retrieves the tag specific data like storage size, hardware type and production date. 
This information is used during tag discovery to determine that the tag is of type **Mifare DESFire EV2 or EV3**. If the tag is not of these
("allowed") types the further processing is disabled to avoid any (unwanted) damage of unknown or wrong tags. The value return by the command 
is processed in the 'VersionInfo' class that allows an easy access to all returned data fields.

A note on the Master Application and it's authentication. As this app isn't touching the Master Application this command is bundled in the UI 
with an 'authenticateLegacy' call to the 'AuthenticateDesfireLegacy' class. If your Master Application Key is changed to an AES key this command 
won't run properly.

You may be think *Why is there a dedicated method to read the tag's UID - it is show after tapping the tag to the reader ?* and you're right. 
When using a tag with fabric settings the tag's UID is part of the regular process between card reader and tag. The reveal of the UID is 
acceptable when the tag is used e.g. as hotel room access card. But think of a card that is used in a smart city for several actions. The card 
holder get's **trackable** as each card reader knows "*this card was presented to me yesterday*". For that reason the tag can get personalized 
for a **random UID** that is shown to the reader. If this option is enabled only a reader with the knowledge of the Master or any Application 
key is been able to read this information - this is a plus on privacy. So don't forget - the **get tag UID** method is available after a successfully 
authentication only.

### Originality signature commands

The **Originality Signature Verification** allows verification of the genuineness of MIFARE DESFire Light (MF2DL(H)x0). Two ways are offered 
to check the originality of the PICC: the first is based on a symmetric authentication, the second works on the verification of an asymmetric 
signature retrieved from the card. As the first way is usable after an "AuthenticateLRPFirst" "or NonFirst" and these authentication methods 
are not supported by the library only the second way is in use. There are 3 steps to verify the signature:
1) read the tag's UID (see "General commands")
2) read the tag's originality signature
3) verify the signature

The library offers two ways to read the signature: **read signature** and **read signature full**. The first method is run without any previous 
authentication (e.g. directly after tapping the tag) and the second will proceed after an authentication with any key only, so the best way is 
to select an application and use the visible authentication buttons for this first.    

The third step is **verification of the signature** - as this is not a tag command it is outsourced to the **Cryptography class** where all of 
the calculations are done. The app bundles the "read tag UID" and "read signature full" commands and then verifies the result. 

From the DESFire Light datasheet: *The NXPOriginalitySignature is computed over the UID with the use of asymmetric cryptographic algorithm 
Elliptic Curve Cryptography Digital Signature Algorithm (ECDSA), see [14]. No hash is computed: M is directly used as H. The NXP Originality 
Signature calculation uses curve secp224r1.*

## Why does the app stops working ?

Sometimes the app seems to freeze and does no longer communicate with the tag. This happens as there are timeouts in the tag reader and the tag itself. On 
my real device a successful "workaround" is to call the "task manager" on the  smartphone and click on the open application again, that way is is reset and 
accepts to connect to the tag again.

Want to know more about [DESFire file operations](desfire_ev3_file_operations.md)

Want to know more about [DESFire Transaction MAC file operations](desfire_ev3_transaction_mac_file_operations.md)

Want to know more about [DESFire authentication](desfire_ev3_authentication.md)

How to prepare a DESFire EV3 to work as a DESFire Light tag: [setup DESFire Light environment](desfire_ev3_setup_desfire_light_environment.md)

[]()




