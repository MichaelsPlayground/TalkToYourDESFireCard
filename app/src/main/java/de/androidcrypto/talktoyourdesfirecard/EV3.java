package de.androidcrypto.talktoyourdesfirecard;

public class EV3 {

    public static String getErrorCode(byte oneByteResponse) {
        byte[] errorCode = new byte[]{(byte) 0x91, oneByteResponse};
        return getErrorCode(errorCode);
    }

    public static String getErrorCode(byte[] twoByteResponse) {
        if (twoByteResponse == null) {
            return "response is null";
        }
        if (twoByteResponse.length != 2) {
            return "response is not of 2 bytes length";
        }
        byte sw1 = twoByteResponse[0];
        if (sw1 != (byte) 0x91) {
            return "first byte is not 0x91";
        }
        byte sw2 = twoByteResponse[1];
        switch (sw2) {
            // full ev1 error codes
            case (byte) 0x00: return "00 success";
            case (byte) 0x0c: return "0C no change";
            case (byte) 0x0e: return "0E out of EPROM memory";
            case (byte) 0x1c: return "1C illegal command";
            case (byte) 0x1e: return "1E integrity error";
            case (byte) 0x40: return "40 No such key error";
            case (byte) 0x6e: return "6E Error (ISO?) error";
            case (byte) 0x7e: return "7E Length error";
            case (byte) 0x97: return "97 Crypto error";
            case (byte) 0x9D: return "9D Permission denied error";
            case (byte) 0x9e: return "9E Parameter error";
            case (byte) 0xA0: return "A0 application not found error";
            case (byte) 0xAE: return "AE authentication error";
            case (byte) 0xAF: return "AF Additional frame (more data to follow before final status code)";
            case (byte) 0xBE: return "BE boundary error";
            case (byte) 0xC1: return "C1 card integrity error";
            case (byte) 0xCA: return "CA command aborted error";
            case (byte) 0xCD: return "CD card disabled error";
            case (byte) 0xCE: return "CE count error";
            case (byte) 0xDE: return "DE duplicate error";
            case (byte) 0xEE: return "EE eeprom error";
            case (byte) 0xF0: return "F0 File not found error";
            case (byte) 0xF1: return "F1 file integrity error";
            // self defined error codes
            case (byte) 0xFE: return "FE missing authentication error"; // error from DesfireAuthenticateEv2 class, not from PICC
            case (byte) 0xFF: return "FF undefined error";
        }
        return "undefined error code";
    }
}
