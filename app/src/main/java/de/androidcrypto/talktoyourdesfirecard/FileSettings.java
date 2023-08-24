package de.androidcrypto.talktoyourdesfirecard;

import java.util.Arrays;

/**
 * This class takes the PICC response of the getFileSettings command (0x5f)
 *
 * Note: regarding the Transaction MAC file some additional data should be read out, skipped here
 *
 */

/**
 * The class is running as expected for fileSettingResponses for a file without enabled
 * Secure Data Messaging (SDM)
 *
 * As there is no public available documentation regarding this feature the class uses test data
 * for an NTAG424DNA tag:
 * NTAG 424 DNA NT4H2421Gx.pdf: https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf
 * NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf: https://www.nxp.com/docs/en/application-note/AN12196.pdf
 *
 * I cannot test the analyzed data with a real tag and I'm suspicious with the analyzed values for
 * all of the offset and length values following the SDM Access Rights, so please do not rely on these values !
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
    private byte tmkFileOption;
    private byte tmKeyOption;
    private byte tmKeyVersion;
    private byte[] tmcLimit; // is optional and present if Bit5 of FileOption set. Length is depending on AES mode (4 byte) or LRP mde (2 byte)
    // section for sdm enriched file settings
    private boolean isNonStandardFileOption = false; // is set to true when fileOptions > 3
    private boolean isSdmEnabled = false;
    private byte sdmFileOption; // in use when isSdmEnabled == true
    private boolean isSdmOptionsBit0_Encode = false; // Encoding mode, only true ASCII when set
    // bit 1-3 RFU
    private boolean isSdmOptionsBit4_SDMENCFileData = false; // SDMENCFileData, true = enabled
    private boolean isSdmOptionsBit5_SDMReadCtrLimit = false; // SDMReadCtrLimit, true = enabled
    private boolean isSdmOptionsBit6_SDMReadCtr = false; // SDMReadCtr, true = enabled
    private boolean isSdmOptionsBit7_UID = false; // UID (only for mirroring), true = enabled
    private byte[] SDM_AccessRights = new byte[2];
    private byte SDM_MetaReadAccessRight;
    private byte SDM_FileReadAccessRight;
    private byte SDM_CtrRetAccessRight;
    private byte[] SDM_UIDOffset;
    private byte[] SDM_ReadCtrOffset;
    private byte[] SDM_PICCDataOffset;
    private byte[] SDM_MACInputOffset;
    private byte[] SDM_ENCOffset;
    private byte[] SDM_ENCLength;
    private byte[] SDM_MACOffset;
    private byte[] SDM_ReadCtrLimit;

    private byte[] completeResponse; // the complete data returned on getFileSettings command
    private int completeResponseLength; // the complete data length
    private boolean isUnexpectedResponseLength = false;
    private String unexpectedResponseLengthPositionName = "";

    public static final int STANDARD_FILE_TYPE = 0;
    public static final int BACKUP_FILE_TYPE = 1;
    public static final int VALUE_FILE_TYPE = 2;
    public static final int LINEAR_RECORD_FILE_TYPE = 3;
    public static final int CYCLIC_RECORD_FILE_TYPE = 4;
    public static final int TRANSACTION_MAC_FILE_TYPE = 5;
    public static final String STANDARD_FILE_TYPE_NAME = "Standard";
    public static final String BACKUP_FILE_TYPE_NAME = "Backup";
    public static final String VALUE_FILE_TYPE_NAME = "Value";
    public static final String LINEAR_RECORD_FILE_TYPE_NAME = "Linear record";
    public static final String CYCLIC_RECORD_FILE_TYPE_NAME = "Cyclic record";
    public static final String TRANSACTION_MAC_FILE_TYPE_NAME = "Transaction MAC";
    public static final String COMMUNICATION_SETTING_NAME_PLAIN = "Plain";
    public static final String COMMUNICATION_SETTING_NAME_CMACED = "CMACed";
    public static final String COMMUNICATION_SETTING_NAME_ENCRYPTED = "Encrypted";

    public FileSettings(byte fileNumber, byte[] completeResponse) {
        this.fileNumber = fileNumber;
        this.completeResponse = completeResponse;
        if (completeResponse == null) {
            isUnexpectedResponseLength = true;
            return;
        }
        this.completeResponseLength = completeResponse.length;
        if (completeResponse.length < 6) {
            isUnexpectedResponseLength = true;
            return;
        }
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

            tmkFileOption = completeResponse[position]; // need to differentiate later, e.g. bit 1-0 contain the communicationSettings
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

            // todo need to analyze accessRightsRw - if the key is 'F' / 15 then the CommitReaderId feature is disabled, '0' to 'E' (0..14) is enabled and auth necessary with this  key !

            position ++;
            tmKeyOption = completeResponse[position]; // todo need to differentiate later, but at the moment only bit 1-0 are set to 10b = AES
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
            // enhancement for Secure Data Management (SDM) enriched content
            if (communicationSettings > 3) {
                // this is a SDM enriched getFileSettings respond because the fileOption
                // (the byte where the communication settings are included) is 40 or something else
                // we need to work on bit basis now to find out all options
                isNonStandardFileOption = true;
                // as more data may follow we are setting the position to the new value
                position = position + 3; // position after fileSize
                analyzeSdmEnrichedFileSettings(position);
            } else {
                // this is a regular getFileSettingsResponse, finishing
                return;
            }
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
            case (byte) 0x00: return STANDARD_FILE_TYPE_NAME;
            case (byte) 0x01: return BACKUP_FILE_TYPE_NAME;
            case (byte) 0x02: return VALUE_FILE_TYPE_NAME;
            case (byte) 0x03: return LINEAR_RECORD_FILE_TYPE_NAME;
            case (byte) 0x04: return CYCLIC_RECORD_FILE_TYPE_NAME;
            case (byte) 0x05: return TRANSACTION_MAC_FILE_TYPE_NAME;
            default: return "Unknown";
        }
    }

    /**
     * if byte 1 of the fileSettingsRespond ("communication settings") is > 3 we received a
     * Secure Data Messaging (SDM) enriched fileSettingsRespond
     * Analyzing is done on bit basis of byte 1 and reading additional optional values
     * This is based on NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf and
     * NTAG 424 DNA NT4H2421Gx.pdf 'getFileSettings' pages 69 - 71
     *                         and 'changeFileSettings' page 65 - 71
     *
     * At the moment the SDM enriched fileSettings may occur on Standard files only ?
     */
    private void analyzeSdmEnrichedFileSettings(int position) {
        // typical getFileSettings respond 00 40 00 E0 00 01 00 C1 F1 21 20 00 00 43 00 00 43 00 00 (19 bytes)
        // I'm using the name 'fileOption' for byte 1 that is communication settings without SDM
        sdmFileOption = communicationSettings;
        boolean fileOptionBit0 = testBit(sdmFileOption, 0);
        // communication settings: if bit0 is unset: Plain, No protection: message is transmitted in plain text
        // communication settings: if bit0 is set:   MACed or FullEnciphered, depending on bit1
        boolean fileOptionBit1 = testBit(sdmFileOption, 1); // communication settings
        // communication settings: if bit1 is unset: MACed, MAC protection for integrity and authenticity
        // communication settings: if bit1 is set:   FullEnciphered, Full protection for integrity, authenticity and confidentiality, also referred to as "Full Protection" mode
        // new value for communication settings
        if (!fileOptionBit0) {
            // plain mode
            communicationSettings = (byte) 0x00;
            communicationSettingsName = COMMUNICATION_SETTING_NAME_PLAIN;
        } else {
            // MACed or FullEnciphered
            if (!fileOptionBit1) {
                communicationSettings = (byte) 0x01;
                communicationSettingsName = COMMUNICATION_SETTING_NAME_CMACED;
            } else {
                communicationSettings = (byte) 0x03;
                communicationSettingsName = COMMUNICATION_SETTING_NAME_ENCRYPTED;
            }
        }
        // analyzing the other bits
        // bits 2-5 and 7 are RFU
        boolean fileOptionBit6 = testBit(sdmFileOption, 6); // if bit6 is unset: Secure Dynamic Messaging and Mirroring disabled
        if (fileOptionBit6) {
            // sdm is enabled
            isSdmEnabled = true;
        } else {
            // sdm is disabled
            isSdmEnabled = false;
        }

        // if not enabled no further to do's, finish analysis
        if (!isSdmEnabled) {
            return;
        }
        // now we can analyze for the next byte that is SDM options
        byte sdmOptions = completeResponse[position];
        isSdmOptionsBit0_Encode = testBit(sdmOptions, 0); // Encoding mode, only true ASCII when set
        // bit 1-3 RFU
        isSdmOptionsBit4_SDMENCFileData = testBit(sdmOptions, 4); // SDMENCFileData, true = enabled
        isSdmOptionsBit5_SDMReadCtrLimit = testBit(sdmOptions, 5); // SDMReadCtrLimit, true = enabled
        isSdmOptionsBit6_SDMReadCtr = testBit(sdmOptions, 6); // SDMReadCtr, true = enabled
        isSdmOptionsBit7_UID = testBit(sdmOptions, 7); // UID (only for mirroring), true = enabled
        position ++;
        // SDMAccessRights, 2 bytes, [Optional, present if FileOption[Bit 6] set]
        // at this point FileOption bit6 is set (SDM enabled)
        SDM_AccessRights = Arrays.copyOfRange(completeResponse, position, position + 2);
        position = position + 2;

        /*
        sdmAccessRights F121 are mapped to:
        F = RFU, please just use F as value
        1 = SDM Counter Ret Access Rights 0x00 to 0x0D: Targeted AppKey 0x0E : Free 0x0F : No Access
        2 = SDM Meta Read Access Rights   0x00 to 0x0D: Encrypted PICC data mirroring using the targeted AppKey 0x0E : Plain PICC data mirroring 0x0F : No PICC data mirroring
        1 = SDM File Read Access Rights   0x00 to 0x0D: Targeted AppKey 0x0F : No SDM for Reading
         */
        // SDM_AccessRights = Utils.hexStringToByteArray("1234"); // testing
        SDM_CtrRetAccessRight = (byte) (SDM_AccessRights[0] & 0x0f);
        SDM_MetaReadAccessRight = (byte) ((SDM_AccessRights[1] >> 4) & 0x0f);
        SDM_FileReadAccessRight = (byte) (SDM_AccessRights[1] & 0x0f);

        // before trying to get the data for each element a length check is done to prevent ArrayIndexOutOfBoundsException

        // UIDOffset 3 bytes
        // [Optional, present if ((SDMOptions[Bit 7] = 1b) AND (SDMMetaRead access right = Eh)]
        // Mirror position (LSB first) for UID
        // 0h .. (FileSize - UIDLength) = Offset within the file
        if (isSdmOptionsBit7_UID && (SDM_MetaReadAccessRight == (byte) 0x0E)) {
            checkUnexpectedResponseLength(position, 3, "UIDOffset");
            SDM_UIDOffset = Arrays.copyOfRange(completeResponse, position, position + 3);
            position = position + 3;
        }

        // SDMReadCtrOffset 3 bytes
        // [Optional, present if ((SDMOptions[Bit 6] = 1b) AND (SDMMetaRead access right = Eh)]
        // Mirror position (LSB first) for SDMReadCtr
        // 0h .. (FileSize - SDMReadCtrLength) = Offset within the file
        // FFFFFFh = No SDMReadCtr mirroring
        if (isSdmOptionsBit6_SDMReadCtr && (SDM_MetaReadAccessRight == (byte) 0x0E)) {
            if(!checkUnexpectedResponseLength(position, 3, "ReadCtrOffset")) return;
            SDM_ReadCtrOffset = Arrays.copyOfRange(completeResponse, position, position + 3);
            position = position + 3;
        }

        // PICCDataOffset 3 bytes
        // [Optional, present if SDMMetaRead access right =0h..4h] - Note: 4h value is for NTAG424DNA
        // Mirror position (LSB first) for encrypted PICCData
        // 0h .. (FileSize - PICCDataLength) = Offset within the file
        if ((SDM_MetaReadAccessRight >= 0) && (SDM_MetaReadAccessRight < 14)) {
            if(!checkUnexpectedResponseLength(position, 3, "MetaReadAccessRight")) return;
            SDM_PICCDataOffset = Arrays.copyOfRange(completeResponse, position, position + 3);
            position = position + 3;
        }

        // SDMMACInputOffset 3 bytes
        // [Optional, present if SDMFileRead access right != Fh]
        // Offset in the file where the SDM MAC computation starts (LSB first)
        // 0h .. (SDMMACOffset) = Offset within the file
        if (SDM_FileReadAccessRight != (byte) 0x0F) {
            if(!checkUnexpectedResponseLength(position, 3, "MACInputOffset")) return;
            SDM_MACInputOffset = Arrays.copyOfRange(completeResponse, position, position + 3);
            position = position + 3;
        }

        // SDMENCOffset 3 bytes
        // [Optional, present if ((SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 1b))]
        // SDMENCFileData mirror position (LSB first)
        // SDMMACInputOffset .. (SDMMACOffset - 32) = Offset within the file
        if ((isSdmOptionsBit4_SDMENCFileData) && (SDM_FileReadAccessRight != (byte) 0x0F)) {
            if(!checkUnexpectedResponseLength(position, 3, "ENCOffset")) return;
            SDM_ENCOffset = Arrays.copyOfRange(completeResponse, position, position + 3);
            position = position + 3;
        }

        // SDMENCLength 3 bytes
        // Optional, present if ((SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 1b))]
        // Length of the SDMENCFileData (LSB first)
        // 32 .. (SDMMACOffset - SDMENCOffset) = Offset within the file, must be multiple of 32
        if ((isSdmOptionsBit4_SDMENCFileData) && (SDM_FileReadAccessRight != (byte) 0x0F)) {
            if(!checkUnexpectedResponseLength(position, 3, "ENCLength")) return;
            SDM_ENCLength = Arrays.copyOfRange(completeResponse, position, position + 3);
            position = position + 3;
        }

        // SDMMACOffset 3 bytes
        // [Optional, present if SDMFileRead access right != Fh]
        // SDMMAC mirror position (LSB first)
        // SDMMACInputOffset .. (FileSize - 16) [if (SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 0b)] = Offset within the file
        // (SDMENCOffset + SDMENCLength) .. (FileSize- 16) [if (SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 1b)] = Offset within the file
        if (SDM_FileReadAccessRight != (byte) 0x0F) {
            if(!checkUnexpectedResponseLength(position, 3, "MACOffset")) return;
            SDM_MACOffset = Arrays.copyOfRange(completeResponse, position, position + 3);
            position = position + 3;
        }

        // SDMReadCtrLimit 3 bytes
        // [Optional, present if SDMOptions[Bit 5] = 1b]
        // SDMReadCtrLimit value (LSB first)
        // Full range
        if (isSdmOptionsBit5_SDMReadCtrLimit) {
            if(!checkUnexpectedResponseLength(position, 3, "ReadCtrLimit")) return;
            SDM_ReadCtrLimit = Arrays.copyOfRange(completeResponse, position, position + 3);
            // position = position + 3; // finished
        }

        // typical getFileSettings respond 00 40 00 E0 00 01 00 C1 F1 21 20 00  00 43 00 00 43 00 00 (19 bytes)
        // response from NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf, page 21
        // response from 0040EEEE000100D1FE00 1F 00004400004400002000006A0000

    }

    private boolean checkUnexpectedResponseLength(int position, int readLength, String positionName) {
        if ((position + readLength) > completeResponseLength) {
            isUnexpectedResponseLength = true;
            unexpectedResponseLengthPositionName = positionName;
            return false;
        }
        return true;
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
            sb.append("fileOption: ").append(tmkFileOption).append("\n");
            sb.append("tmKeyOption: ").append(tmKeyOption).append("\n");
            sb.append("tmKeyVersion: ").append(tmKeyVersion).append("\n");
            sb.append("tmcLimit: ").append(bytesToHexNpeUpperCase(tmcLimit)).append("\n");
            sb.append("don't rely on communicationSettings and tmcLimit !").append("\n");
        }
        if (isNonStandardFileOption) {
            sb.append("non standard fileOption found").append("\n");
            sb.append("sdmFileOption: ").append(byteToHex(sdmFileOption)).append("\n");
            sb.append("isSdmEnabled: ").append(isSdmEnabled).append("\n");
            sb.append("isSdmOptionsBit0_Encode: ").append(isSdmOptionsBit0_Encode).append("\n");
            sb.append("isSdmOptionsBit4_SDMENCFileData: ").append(isSdmOptionsBit4_SDMENCFileData).append("\n");
            sb.append("isSdmOptionsBit5_SDMReadCtrLimit: ").append(isSdmOptionsBit5_SDMReadCtrLimit).append("\n");
            sb.append("isSdmOptionsBit6_SDMReadCtr: ").append(isSdmOptionsBit6_SDMReadCtr).append("\n");
            sb.append("isSdmOptionsBit7_UID: ").append(isSdmOptionsBit7_UID).append("\n");
            sb.append("SDM_AccessRights: ").append(bytesToHexNpeUpperCase(SDM_AccessRights)).append("\n");
            sb.append("SDM_MetaReadAccessRight: ").append(byteToHex(SDM_MetaReadAccessRight)).append("\n");
            sb.append("SDM_FileReadAccessRight: ").append(byteToHex(SDM_FileReadAccessRight)).append("\n");
            sb.append("SDM_CtrRetAccessRight: ").append(byteToHex(SDM_CtrRetAccessRight)).append("\n");
            sb.append("optional values depending on bit settings (LSB)").append("\n");
            sb.append("SDM_UIDOffset      ").append(bytesToHexNpeUpperCase(SDM_UIDOffset)).append("\n");
            sb.append("SDM_ReadCtrOffset  ").append(bytesToHexNpeUpperCase(SDM_ReadCtrOffset)).append("\n");
            sb.append("SDM_PICCDataOffset ").append(bytesToHexNpeUpperCase(SDM_PICCDataOffset)).append("\n");
            sb.append("SDM_MACInputOffset ").append(bytesToHexNpeUpperCase(SDM_MACInputOffset)).append("\n");
            sb.append("SDM_ENCOffset      ").append(bytesToHexNpeUpperCase(SDM_ENCOffset)).append("\n");
            sb.append("SDM_ENCLength      ").append(bytesToHexNpeUpperCase(SDM_ENCLength)).append("\n");
            sb.append("SDM_MACOffset      ").append(bytesToHexNpeUpperCase(SDM_MACOffset)).append("\n");
            sb.append("SDM_ReadCtrLimit   ").append(bytesToHexNpeUpperCase(SDM_ReadCtrLimit)).append("\n");
            if (isUnexpectedResponseLength) {
                sb.append("unexpectedResponseLength of reading ").append(unexpectedResponseLengthPositionName).append("\n");
            }
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

    // position is 0 based starting from right to left
    private static byte setBitInByte(byte input, int pos) {
        return (byte) (input | (1 << pos));
    }

    // position is 0 based starting from right to left
    private static byte unsetBitInByte(byte input, int pos) {
        return (byte) (input & ~(1 << pos));
    }

    // https://stackoverflow.com/a/29396837/8166854
    private static boolean testBit(byte b, int n) {
        int mask = 1 << n; // equivalent of 2 to the nth power
        return (b & mask) != 0;
    }

    // https://stackoverflow.com/a/29396837/8166854
    private static boolean testBit(byte[] array, int n) {
        int index = n >>> 3; // divide by 8
        int mask = 1 << (n & 7); // n modulo 8
        return (array[index] & mask) != 0;
    }

    // get the byte encoded value of a 4 bit chunk, index is counting from LEFT to RIGHT
    // https://stackoverflow.com/a/14533405/8166854
    private byte getByteFromByteArray4BitChunk(byte[] data, int index) {
        if (index % 2 == 0) {
            return (byte) (data[index/2] >>> 4); // unsigned bit shift
        }else{
            return (byte) (data[index/2] & 0x0F);
        }
    }

    /**
     * section for getter
     */

    public byte getFileNumber() {
        return fileNumber;
    }

    public int getFileNumberInt() {
        return (int) fileNumber;
    }

    public byte getFileType() {
        return fileType;
    }

    public String getFileTypeName() {
        return fileTypeName;
    }

    public byte getCommunicationSettings() {
        return communicationSettings;
    }

    public String getCommunicationSettingsName() {
        return communicationSettingsName;
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

    public boolean isNonStandardFileOption() {
        return isNonStandardFileOption;
    }

    public boolean isSdmEnabled() {
        return isSdmEnabled;
    }

    public boolean isSdmOptionsBit0_Encode() {
        return isSdmOptionsBit0_Encode;
    }

    public boolean isSdmOptionsBit4_SDMENCFileData() {
        return isSdmOptionsBit4_SDMENCFileData;
    }

    public boolean isSdmOptionsBit5_SDMReadCtrLimit() {
        return isSdmOptionsBit5_SDMReadCtrLimit;
    }

    public boolean isSdmOptionsBit6_SDMReadCtr() {
        return isSdmOptionsBit6_SDMReadCtr;
    }

    public boolean isSdmOptionsBit7_UID() {
        return isSdmOptionsBit7_UID;
    }

    public byte getSDM_MetaReadAccessRight() {
        return SDM_MetaReadAccessRight;
    }

    public byte getSDM_FileReadAccessRight() {
        return SDM_FileReadAccessRight;
    }

    public byte getSDM_CtrRetAccessRight() {
        return SDM_CtrRetAccessRight;
    }

    public byte[] getSDM_UIDOffset() {
        return SDM_UIDOffset;
    }

    public byte[] getSDM_ReadCtrOffset() {
        return SDM_ReadCtrOffset;
    }

    public byte[] getSDM_PICCDataOffset() {
        return SDM_PICCDataOffset;
    }

    public byte[] getSDM_MACInputOffset() {
        return SDM_MACInputOffset;
    }

    public byte[] getSDM_ENCOffset() {
        return SDM_ENCOffset;
    }

    public byte[] getSDM_ENCLength() {
        return SDM_ENCLength;
    }

    public byte[] getSDM_MACOffset() {
        return SDM_MACOffset;
    }

    public byte[] getSDM_ReadCtrLimit() {
        return SDM_ReadCtrLimit;
    }
}
