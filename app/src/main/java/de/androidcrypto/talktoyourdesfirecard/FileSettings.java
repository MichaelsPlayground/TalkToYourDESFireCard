package de.androidcrypto.talktoyourdesfirecard;

import java.util.Arrays;

/**
 * This class takes the PICC response of the getFileSettings command (0x5f)
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
        if (completeResponse.length < 7) return;
        analyze();
    }

    private void analyze() {
        int position = 0;
        fileType = completeResponse[0]; // needed to know the kind of variables to fill
        fileTypeName = getFileTypeName(fileType);
        position ++;
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
        }
        return sb.toString();
    }

    private String byteToHex(Byte input) {
        return String.format("%02X", input);
    }

    private int byteArrayLength3InversedToInt(byte[] data) {
        return (data[2] & 0xff) << 16 | (data[1] & 0xff) << 8 | (data[0] & 0xff);
    }

    private static int byteArrayLength4InversedToInt(byte[] bytes) {
        return bytes[3] << 24 | (bytes[2] & 0xFF) << 16 | (bytes[1] & 0xFF) << 8 | (bytes[0] & 0xFF);
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
