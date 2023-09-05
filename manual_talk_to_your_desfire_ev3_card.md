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

## Why does the app stops working ?

Sometimes the app seems to freeze and does no longer communicate with the tag. This happens as there are timeouts in the tag reader and the tag itself. On 
my real device a successful "workaround" is to call the "task manager" on the  smartphone and click on the open application again, that way is is reset and 
accepts to connect to the tag again.

Want to know more about [DESFire file operations](desfire_ev3_file_operations.md)

Want to know more about [DESFire Transaction MAC file operations](desfire_ev3_transaction_mac_file_operations.md)

Want to know more about [DESFire authentication](desfire_ev3_authentication.md)

How to prepare a DESFire EV3 to work as a DESFire Light tag: [setup DESFire Light environment](desfire_ev3_setup_desfire_light_environment.md)

[]()




