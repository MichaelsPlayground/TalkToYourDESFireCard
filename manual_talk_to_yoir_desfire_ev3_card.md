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
should work properly with these tags as well. As I do not have DESFire EV1 or EV2 tags available I could not 
test the functionality and the answer is *I don't know.*.

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
2) The app will create a new application with applicationID A1A2A3. The app will have 5 AES based application keys.
3) There are no restrictions in application on file and directory handling (default settings).
4) In the new application files are created with these file numbers and access rights (R & W 1, CAR 2, R 3, W 4):
       
- 01 Standard File, 256 file size, communication mode Plain
- 02 Standard File, 256 file size, communication mode MACed
- 03 Standard File, 256 file size, communication mode Full enciphered
- 04 Backup File, 32 file size, communication mode Plain
- 05 Backup File, 32 file size, communication mode MACed
- 06 Standard File, 32 file size, communication mode Full enciphered
- 07 Value File, communication mode Plain
- 08 Value File, communication mode MACed
- 09 Value File, communication mode Full enciphered
- 10 Linear Record file, 32 record size, 3 maximum number of records, communication mode Plain
- 11 Linear Record file, 32 record size, 3 maximum number of records, communication mode MACed
- 12 Linear Record file, 32 record size, 3 maximum number of records, communication mode Full enciphered
- 13 Cyclic Record file, 32 record size, 4 maximum number of records, communication mode Plain
- 14 Cyclic Record file, 32 record size, 4 maximum number of records, communication mode MACed
- 15 Cyclic Record file, 32 record size, 4 maximum number of records, communication mode Full enciphered






























