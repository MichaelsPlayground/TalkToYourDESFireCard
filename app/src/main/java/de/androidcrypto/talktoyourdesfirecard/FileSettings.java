package de.androidcrypto.talktoyourdesfirecard;

import java.util.Arrays;

/**
 * This class takes the PICC response of the getFileSettings command (0x5f)
 *
 * Note: regarding the Transaction MAC file some additional data should be read out, skipped here
 *
 */

public class FileSettings {

    private byte fileNumber;
    private byte fileType;
    private String fileTypeName;
    private byte communicationSettings;
    private String communicationSettingsName;
    private byte accessRightsRwCar; // Right & Write access key | Change access key
    private byte accessRightsRW; // Read access key | Write access key
    private int accessRightsRw, accessRightsCar, accessRightsR, accessRightsW;
    private byte[] fileSize; // 3 bytes, available for Standard & Backup files only, beware: this data is LSB
    private int fileSizeInt;
    // the following variables are available for value files only
    private byte[] valueMin;
    private byte[] valueMax;
    private byte[] valueLimitedCredit;
    private byte valueLimitedCreditAvailable;
    // the following variables are available for linear record and cyclic record files only
    private byte[] recordSize; // 3 bytes beware: this data is LSB
    private int recordSizeInt;
    private byte[] recordsMax; // 3 bytes
    private int recordsMaxInt;
    private byte[] recordsExisting; // 3 bytes
    private int recordsExistingInt;
    // the following variables are available for transaction mac files
    byte fileOption;
    byte tmKeyOption;
    byte tmKeyVersion;
    byte[] tmcLimit; // is optional and present if Bit5 of FileOption set. Length is depending on AES mode (4 byte) or LRP mde (2 byte)

    private byte[] completeResponse; // the complete data returned on getFileSettings command

    public static final String STANDARD_FILE_TYPE = "Standard";
    public static final String BACKUP_FILE_TYPE = "Backup";
    public static final String VALUE_FILE_TYPE = "Value";
    public static final String LINEAR_RECORD_FILE_TYPE = "Linear record";
    public static final String CYCLIC_RECORD_FILE_TYPE = "Cyclic record";
    public static final String TRANSACTION_MAC_FILE_TYPE = "Transaction MAC";
    public static final String COMMUNICATION_SETTING_NAME_PLAIN = "Plain";
    public static final String COMMUNICATION_SETTING_NAME_CMACED = "CMACed";
    public static final String COMMUNICATION_SETTING_NAME_ENCRYPTED = "Encrypted";

    public FileSettings(byte fileNumber, byte[] completeResponse) {
        this.fileNumber = fileNumber;
        this.completeResponse = completeResponse;
        if (completeResponse == null) return;
        if (completeResponse.length < 6) return;
        analyze();
    }

    private void analyze() {
        int position = 0;
        fileType = completeResponse[0]; // needed to know the kind of variables to fill
        fileTypeName = getFileTypeName(fileType);
        position ++;
        // if it is a Transaction MAC file it is a different setup
        // see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 78 for details
        // todo some sub fields are not not read out, see 'need to differentiate later'
        if (fileType == (byte) 0x05) {
            // transaction mac file

            // fixed fileSize data
            //
            fileSizeInt = 12; // default
            fileSize = intTo3ByteArrayInversed(fileSizeInt);

            fileOption = completeResponse[position]; // need to differentiate later, e.g. bit 1-0 contain the communicationSettings
            communicationSettings = (byte) 0x00; // todo change, this is hardcoded and not read
            if (communicationSettings == (byte) 0x00) communicationSettingsName = COMMUNICATION_SETTING_NAME_PLAIN;
            if (communicationSettings == (byte) 0x01) communicationSettingsName = COMMUNICATION_SETTING_NAME_CMACED;
            if (communicationSettings == (byte) 0x03) communicationSettingsName = COMMUNICATION_SETTING_NAME_ENCRYPTED;
            position ++;
            accessRightsRwCar = completeResponse[position];
            position ++;
            accessRightsRW = completeResponse[position];
            // get the values vor RW, Car, R and W
            // lowNibble = yourByte & 0x0f; highNibble = (yourByte >> 4) & 0x0f;
            // You can also do: lowNibble = yourByte & 0x0f; highNibble = yourByte >>> 4;
            accessRightsRw = (accessRightsRwCar >> 4) & 0x0f;
            accessRightsCar = accessRightsRwCar & 0x0f;
            accessRightsR =  (accessRightsRW >> 4) & 0x0f;
            accessRightsW =  accessRightsRW & 0x0f;

            position ++;
            tmKeyOption = completeResponse[position]; // need to differentiate later, but at the moment only bit 1-0 are set to 10b = AES
            position ++;
            tmKeyVersion = completeResponse[position];
            // the next steps depend on the length
            int completeResponseLength = completeResponse.length;
            if (completeResponseLength == 6) {
                // we are done
                return;
            }
            position ++;
            if (completeResponseLength == 8) {
                // LRP mode, tmcLimit  is 2 bytes long // todo is the limit LSB coded ??
                tmcLimit = Arrays.copyOfRange(completeResponse, position, position + 2);
                return;
            }
            if (completeResponseLength == 10) {
                // AES mode, tmcLimit  is 4 bytes long // todo is the limit LSB coded ??
                tmcLimit = Arrays.copyOfRange(completeResponse, position, position + 4);
                return;
            }
            return;
        }

        communicationSettings = completeResponse[position];
        position ++;
        if (communicationSettings == (byte) 0x00) communicationSettingsName = COMMUNICATION_SETTING_NAME_PLAIN;
        if (communicationSettings == (byte) 0x01) communicationSettingsName = COMMUNICATION_SETTING_NAME_CMACED;
        if (communicationSettings == (byte) 0x03) communicationSettingsName = COMMUNICATION_SETTING_NAME_ENCRYPTED;
        accessRightsRwCar = completeResponse[position];
        position ++;
        accessRightsRW = completeResponse[position];
        position ++;
        // get the values vor RW, Car, R and W
        // lowNibble = yourByte & 0x0f; highNibble = (yourByte >> 4) & 0x0f;
        // You can also do: lowNibble = yourByte & 0x0f; highNibble = yourByte >>> 4;
        accessRightsRw = (accessRightsRwCar >> 4) & 0x0f;
        accessRightsCar = accessRightsRwCar & 0x0f;
        accessRightsR =  (accessRightsRW >> 4) & 0x0f;
        accessRightsW =  accessRightsRW & 0x0f;

        fileSize = new byte[3];
        fileSizeInt = 0; // default
        if ((fileType == (byte) 0x00) || (fileType == (byte) 0x01)) {
            // standard and backup file
            fileSize = Arrays.copyOfRange(completeResponse, position, position + 3);
            fileSizeInt = byteArrayLength3InversedToInt(fileSize);
            return;
        }
        if (fileType == (byte) 0x02) {
            // value file
            valueMin = Arrays.copyOfRange(completeResponse, position, position + 4);
            position += 4;
            valueMax = Arrays.copyOfRange(completeResponse, position, position + 4);
            position += 4;
            valueLimitedCredit = Arrays.copyOfRange(completeResponse, position, position + 4);
            position += 4;
            valueLimitedCreditAvailable = completeResponse[position];
            return;
        }
        if ((fileType == (byte) 0x03) || (fileType == (byte) 0x04)) {
            // linear record and cyclic record file
            recordSize = Arrays.copyOfRange(completeResponse, position, position + 3);
            recordSizeInt = byteArrayLength3InversedToInt(recordSize);
            position += 3;
            recordsMax = Arrays.copyOfRange(completeResponse, position, position + 3);
            recordsMaxInt = byteArrayLength3InversedToInt(recordsMax);
            position += 3;
            recordsExisting = Arrays.copyOfRange(completeResponse, position, position + 3);
            recordsExistingInt = byteArrayLength3InversedToInt(recordsExisting);
            return;
        }
    }

    private String getFileTypeName(byte fileType) {
        switch (fileType) {
            case (byte) 0x00: return STANDARD_FILE_TYPE;
            case (byte) 0x01: return BACKUP_FILE_TYPE;
            case (byte) 0x02: return VALUE_FILE_TYPE;
            case (byte) 0x03: return LINEAR_RECORD_FILE_TYPE;
            case (byte) 0x04: return CYCLIC_RECORD_FILE_TYPE;
            case (byte) 0x05: return TRANSACTION_MAC_FILE_TYPE;
            default: return "Unknown";
        }
    }

    public String dump() {
        StringBuilder sb = new StringBuilder();
        sb.append("fileNumber: ").append(byteToHex(fileNumber)).append("\n");
        sb.append("fileType: ").append(fileType).append(" (").append(fileTypeName).append(")").append("\n");
        sb.append("communicationSettings: ").append(byteToHex(communicationSettings)).append(" (").append(communicationSettingsName).append(")").append("\n");
        sb.append("accessRights RW | CAR: ").append(byteToHex(accessRightsRwCar)).append("\n");
        sb.append("accessRights R | W: ").append(byteToHex(accessRightsRW)).append("\n");
        sb.append("accessRights RW:  ").append(accessRightsRw).append("\n");
        sb.append("accessRights CAR: ").append(accessRightsCar).append("\n");
        sb.append("accessRights R:   ").append(accessRightsR).append("\n");
        sb.append("accessRights W:   ").append(accessRightsW).append("\n");
        if ((fileType == (byte) 0x00) || (fileType == (byte) 0x01)) {
            sb.append("fileSize: ").append(byteArrayLength3InversedToInt(fileSize)).append("\n");
        }
        if (fileType == (byte) 0x02) {
            sb.append("valueMin: ").append(byteArrayLength4InversedToInt(valueMin)).append("\n");
            sb.append("valueMax: ").append(byteArrayLength4InversedToInt(valueMax)).append("\n");
            sb.append("valueLimitedCredit: ").append(byteArrayLength4InversedToInt(valueLimitedCredit)).append("\n");
            sb.append("valueLimitedCreditAvailable: ").append(byteToHex(valueLimitedCreditAvailable)).append("\n");
        }
        if ((fileType == (byte) 0x03) || (fileType == (byte) 0x04)) {
            sb.append("recordSize: ").append(recordSizeInt).append("\n");
            sb.append("recordsMax: ").append(recordsMaxInt).append("\n");
            sb.append("recordsExisting: ").append(recordsExistingInt).append("\n");
        }
        if (fileType == (byte) 0x05) {
            sb.append("fileSize: ").append(byteArrayLength3InversedToInt(fileSize)).append("\n");
            sb.append("fileOption: ").append(fileOption).append("\n");
            sb.append("tmKeyOption: ").append(tmKeyOption).append("\n");
            sb.append("tmKeyVersion: ").append(tmKeyVersion).append("\n");
            sb.append("tmcLimit: ").append(bytesToHexNpeUpperCase(tmcLimit)).append("\n");
            sb.append("don't rely on communicationSettings and tmcLimit !").append("\n");
        }
        return sb.toString();
    }

    private String byteToHex(Byte input) {
        return String.format("%02X", input);
    }

    private int byteArrayLength3InversedToInt(byte[] data) {
        return (data[2] & 0xff) << 16 | (data[1] & 0xff) << 8 | (data[0] & 0xff);
    }

    // converts an int to a 3 byte long array inversed = LSB
    public static byte[] intTo3ByteArrayInversed(int value) {
        return new byte[] {
                (byte)value,
                (byte)(value >> 8),
                (byte)(value >> 16)};
    }

    private static int byteArrayLength4InversedToInt(byte[] bytes) {
        return bytes[3] << 24 | (bytes[2] & 0xFF) << 16 | (bytes[1] & 0xFF) << 8 | (bytes[0] & 0xFF);
    }

    private static String bytesToHexNpeUpperCase(byte[] bytes) {
        if (bytes == null) return "";
        StringBuffer result = new StringBuffer();
        for (byte b : bytes)
            result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString().toUpperCase();
    }

    public byte getFileNumber() {
        return fileNumber;
    }

    public int getFileNumberInt() {
        return (int) fileNumber;
    }

    public String getFileTypeName() {
        return fileTypeName;
    }

    public int getAccessRightsRw() {
        return accessRightsRw;
    }

    public int getAccessRightsCar() {
        return accessRightsCar;
    }

    public int getAccessRightsR() {
        return accessRightsR;
    }

    public int getAccessRightsW() {
        return accessRightsW;
    }

    public byte[] getFileSize() {
        return fileSize;
    }

    public int getFileSizeInt() {
        return fileSizeInt;
    }

    public int getRecordSizeInt() {
        return recordSizeInt;
    }

    public int getRecordsMaxInt() {
        return recordsMaxInt;
    }

    public int getRecordsExistingInt() {
        return recordsExistingInt;
    }
}
