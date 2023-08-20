Mifare DESFire on write to a Backup file COMMIT is failing

https://stackoverflow.com/questions/76939288/mifare-desfire-write-to-a-backup-file-commit-is-failing

Tags nfc, Mifare, desfire

When writing to a **Backup** file in **PLAIN** communication mode the **COMMIT command is failing**.

The Backup file is a 32 bytes long file on a Mifare DESFire EV3 tag:

```plaintext
- File ID 0x03: Backup data, 32 bytes
  ~ Communication: plain
  ~ Read key: key #3
  ~ Write key: key #4
  ~ Read/Write key: key #1
  ~ Change key: key #2
```

I ran the authentication with a '**authenticateEV2First**' command using key number 01 (read & write access key) with SUCCESS,  
then run the WRITE command ending with a '0x9100' response meaning SUCCESS.

After this I'm trying to run the **COMMIT** command using this sequence with **FAILURE**:

```plaintext
command:  send apdu --> length: 5 data: 90c7000000
response: received  <-- length: 2 data: 917e
```

The response '0x917E' is meaning 'Length error' so what should be the correct command sequence for the 
COMMIT command when the file is in PLAIN communication mode and the write command is authenticated with 
authenticateEV2First ?





