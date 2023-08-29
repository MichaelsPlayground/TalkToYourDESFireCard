package de.androidcrypto.talktoyourdesfirecard;

import android.nfc.tech.IsoDep;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * this class is responsible for sending to and receiving of data from the DESFire tag. As the size
 * is limited the commands need to get chunked and the response could be split into several parts.
 */

public class CommunicationAdapterOld {

    private static final String TAG = CommunicationAdapterOld.class.getName();

    // constants
    public static final byte OPERATION_OK = (byte) 0x00;
    private static final byte PERMISSION_DENIED = (byte) 0x9D;
    private static final byte AUTHENTICATION_ERROR = (byte) 0xAE;
    public static final byte ADDITIONAL_FRAME = (byte) 0xAF;
    public static final byte STATUS_OK = (byte) 0x91;
    public static final String UNKNOWN_STATUS_NAME = "unknown status code";
    public static final int MAX_CAPDU_SIZE = 55; // this is the limitation size for the complete (wrapped) command
    public static final int MAX_RAPDU_SIZE = 60;

    /* Max APDU sizes to be ISO encapsulated by DESFIRE_TRANSCEIVE()
	   From MIFARE DESFire Functional specification:
	   MAX_CAPDU_SIZE:   "The length of the total wrapped DESFire
	                      command is not longer than 55 byte long."
	   MAX_RAPDU_SIZE:   1 status byte + 59 bytes
	 */

    private final IsoDep isoDep;
    private boolean print = false;
    private boolean debug = false;
    private byte statusCode, errorCode;
    private String statusCodeName, errorCodeName;

    public CommunicationAdapterOld(IsoDep isoDep, boolean print) {
        this.isoDep = isoDep;
        this.print = print;
    }

    /**
     * this is a pure communication with the card, no length checks are done and no receive checks run
     *
     * @param apdu
     * @return the response from the card
     */
    public byte[] sendSimple(byte[] apdu) {
        clearErrorCodes();
        try {
            byte[] response = transceive(apdu);
            statusCode = response[response.length - 2];
            if (statusCode == STATUS_OK) {
                statusCodeName = "OK";
            } else {
                statusCodeName = UNKNOWN_STATUS_NAME;
            }
            errorCode = response[response.length - 1];
            errorCodeName = EV3.getErrorCode(errorCode);
            return response;
        } catch (IOException e) {
            statusCode = (byte) 0xF0;
            statusCodeName = "IOException";
            Log.e(TAG, "sendSimple IOException " + e.getMessage());
            return null;
        }
    }

    /**
     * The all in one solution - wrapping outgoing and incoming data
     * @param apdu
     * @return
     */

    public byte[] sendAllData(byte[] apdu) {
        Log.d(TAG, "sendAllData");
        return sendReceiveChain(sendRequestChain(apdu));
    }

    public byte[] sendReceiveChain(byte[] apdu) {
        byte[] response = sendRequestChain(apdu);
        if (response == null) {
            return null;
        } else {
            return receiveResponseChain(response);
        }
    }

    public byte[] sendRequestChain(byte[] apdu)  {
        /**
         * Note: this method is taken from https://github.com/skjolber/desfire-tools-for-android/blob/master/libfreefare/src/main/java/nfcjlib/core/DESFireAdapter.java
         * and error corrected
         */
        try {
        if (apdu.length <= MAX_CAPDU_SIZE) {
            return transceive(apdu);
        }
        int offset = 5;

        byte nextCommand = apdu[1];
        if (debug) Log.d(TAG, "sendRequestChain with apdu.length >= MAX_CAPDU_SIZE");
        if (debug) Log.d(TAG, "sendRequestChain " + Utils.printData("apdu", apdu));
        if (debug) Log.d(TAG, "sendRequestChain apdu.length: " + apdu.length);

        // strip off the last byte from apdu as it is added through the new wrapCommand
        if (debug) Log.d(TAG, "strip off the last byte of APDU");
        apdu = Arrays.copyOf(apdu, (apdu.length - 1)); // added by AndroidCrypto
        if (debug) Log.d(TAG, "sendRequestChain " + Utils.printData("apdu", apdu));
        if (debug) Log.d(TAG, "sendRequestChain apdu.length: " + apdu.length);

        if (debug) Log.d(TAG, "sendRequestChain MAX_CAPDU_SIZE: " + MAX_CAPDU_SIZE);
        if (debug) Log.d(TAG, "sendRequestChain offset: " + offset);
        while (true) {
            if (debug) Log.d(TAG, "sendRequestChain nextCommand: " + Utils.byteToHex(nextCommand));
            int nextLength = Math.min(MAX_CAPDU_SIZE - 1, apdu.length - offset);
            if (debug) Log.d(TAG, "sendRequestChain nextLength: " + nextLength);
            if (debug) Log.d(TAG, "sendRequestChain offset: " + offset);
            byte[] newDataToSend = Arrays.copyOfRange(apdu, offset, (offset + nextLength));
            if (debug) Log.d(TAG, "sendRequestChain: " + Utils.printData("newDataToSend", newDataToSend));
            byte[] request = wrapMessage(nextCommand, apdu, offset, nextLength);
            if (debug) Log.d(TAG, "sendRequestChain " + Utils.printData("request", request));
            byte[] response = transceive(request);
            if (debug) Log.d(TAG, "sendRequestChain " + Utils.printData("response", response));
            if (response[response.length - 2] != STATUS_OK) {
                Log.e(TAG, "status not OK: " + response[response.length - 2]);
                statusCode = response[response.length - 2];
                statusCodeName = UNKNOWN_STATUS_NAME;
                return null;
                //throw new Exception("Invalid response " + String.format("%02x", response[response.length - 2] & 0xff));
            }

            offset += nextLength;
            if (debug) Log.d(TAG, "sendRequestChain offset: " + offset);
            if (offset == apdu.length) {
                if (debug) Log.d(TAG, "sendRequestChain offset == apdu.length, return");
                return response;
            }
            if (response.length != 2) {
                throw new IllegalArgumentException("Expected empty response payload while transmitting request");
            }
            byte status = response[response.length - 1];
            if (status != ADDITIONAL_FRAME) {
                Log.e(TAG, "error code not OK: " + response[response.length - 1]);
                statusCode = STATUS_OK;
                statusCodeName = "OK";
                errorCode = response[response.length - 1];
                errorCodeName = EV3.getErrorCode(errorCode);
                return null;
                //throw new Exception("PICC error code: " + Integer.toHexString(status & 0xFF));
            }
            nextCommand = ADDITIONAL_FRAME;
            if (debug) Log.d(TAG, "sendRequestChain nextCommand: " + Utils.byteToHex(nextCommand));
        }
        } catch (IOException e) {
            Log.e(TAG, "sendRequestChain IOException " + e.getMessage());
            statusCode = (byte) 0xF0;
            statusCodeName = "IOException";
            return null;
        }
    }

    public byte[] receiveResponseChain(byte[] response) {
        /**
         * Note: this method is taken from https://github.com/skjolber/desfire-tools-for-android/blob/master/libfreefare/src/main/java/nfcjlib/core/DESFireAdapter.java
         */
        if (debug) Log.d(TAG, Utils.printData("response", response));

        if (response[response.length - 2] == STATUS_OK && response[response.length - 1] == OPERATION_OK) {
            statusCode = response[response.length - 2];
            statusCodeName = "OK";
            errorCode = response[response.length - 1];
            errorCodeName = EV3.getErrorCode(errorCode);
            return response;
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
        do {
            if (response[response.length - 2] != STATUS_OK) {
                statusCode = response[response.length - 2];
                statusCodeName = "invalid response";
                errorCode = -1;
                errorCodeName = "n.a.";
                //throw new Exception("Invalid response " + String.format("%02x", response[response.length - 2] & 0xff));
                return null;
            }

            output.write(response, 0, response.length - 2);

            byte status = response[response.length - 1];
            if (status == OPERATION_OK) {
                // todo error correction: add the status for following processes as they may need the status
                output.write(response, response.length - 2, 2); // added

                return output.toByteArray();
            } else if (status != ADDITIONAL_FRAME) {
                statusCode = STATUS_OK;
                statusCodeName = "OK";
                errorCode = status;
                errorCodeName = EV3.getErrorCode(errorCode);
                return null;
                //throw new Exception("PICC error code while reading response: " + Integer.toHexString(status & 0xFF));
            }

            response = transceive(wrapMessage(ADDITIONAL_FRAME));
        } while (true);
        } catch (IOException e) {
            Log.e(TAG, "receiveRequestChain IOException " + e.getMessage());
            statusCode = (byte) 0xF0;
            statusCodeName = "IOException";
            return null;
        }
    }

    /**
     * this communication expects a response that might be longer, indicated by an AF at the end of the response.
     * In that case this method asks for the following data by it's own. When all data are received the card
     * returns the complete response
     *
     * @param apdu
     * @return the response from the card
     */

    public byte[] send(byte[] apdu) {
        clearErrorCodes();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            byte[] recvBuffer = transceive(apdu);
            if (recvBuffer == null) {
                statusCode = -1;
                statusCodeName = UNKNOWN_STATUS_NAME;
                return null;
            }
            if (recvBuffer.length == 1) {
                statusCode = -1;
                statusCodeName = UNKNOWN_STATUS_NAME;
                errorCode = recvBuffer[0];
                errorCodeName = EV3.getErrorCode(errorCode);
                return null;
            }
            while (true) {
                if (recvBuffer[recvBuffer.length - 2] != STATUS_OK) {
                    statusCode = recvBuffer[recvBuffer.length - 2];
                    statusCodeName = UNKNOWN_STATUS_NAME;
                    return null;
                }
                statusCode = STATUS_OK;
                statusCodeName = "OK";
                output.write(recvBuffer, 0, recvBuffer.length - 2);
                byte status = recvBuffer[recvBuffer.length - 1];
                if (status == OPERATION_OK) {
                    errorCode = status;
                    errorCodeName = EV3.getErrorCode(errorCode);
                    if (print) Log.d(TAG, "status " + errorCodeName);
                    break;
                } else if (status == ADDITIONAL_FRAME) {
                    recvBuffer = isoDep.transceive(wrapMessage(ADDITIONAL_FRAME, null));
                } else if (status == PERMISSION_DENIED) {
                    errorCode = status;
                    errorCodeName = EV3.getErrorCode(errorCode);
                    if (print) Log.d(TAG, "status " + errorCodeName);
                    return null;
                    //throw new AccessControlException("Permission denied");
                } else if (status == AUTHENTICATION_ERROR) {
                    errorCode = status;
                    errorCodeName = EV3.getErrorCode(errorCode);
                    if (print) Log.d(TAG, "status " + errorCodeName);
                    return null;
                    //throw new AccessControlException("Authentication error");
                } else {
                    errorCode = status;
                    errorCodeName = EV3.getErrorCode(errorCode);
                    if (print) Log.d(TAG, "status " + errorCodeName);
                    return null;
                    //throw new Exception("Unknown status code: " + Integer.toHexString(status & 0xFF));
                }
            }
            return output.toByteArray();
        } catch (IOException e) {
            Log.e(TAG, "sendSimple IOException " + e.getMessage());
            statusCode = (byte) 0xF0;
            statusCodeName = "IOException";
            return null;
        }
    }

    public byte getStatusCode() {
        return statusCode;
    }

    public byte getErrorCode() {
        return errorCode;
    }

    public String getStatusCodeName() {
        return statusCodeName;
    }

    public String getErrorCodeName() {
        return errorCodeName;
    }

    public byte[] getFullCode() {
        byte[] response = new byte[2];
        response[0] = statusCode;
        response[1] = errorCode;
        return response;
    }

    private void clearErrorCodes() {
        statusCode = -1;
        errorCode = 1;
        statusCodeName = "";
        errorCodeName = "";
    }

    public static byte[] wrapMessage(byte command) {
        return new byte[]{(byte) 0x90, command, 0x00, 0x00, 0x00};
    }

    private byte[] wrapMessage(byte command, byte[] parameters) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write((byte) 0x90);
        stream.write(command);
        stream.write((byte) 0x00);
        stream.write((byte) 0x00);
        if (parameters != null) {
            stream.write((byte) parameters.length);
            stream.write(parameters);
        }
        stream.write((byte) 0x00);
        return stream.toByteArray();
    }

    public byte[] transceive(byte[] apdu) throws IOException {
        if (print) Log.d(TAG, "==> " + Utils.printData("apdu", apdu));
        byte[] response = isoDep.transceive(apdu);
        if (print) Log.d(TAG, "<== " + Utils.printData("response", response));
        return response;
    }

    /**
     * this method is used to re-wrap a command that is too long for one single sending
     * @param command
     * @param parameters
     * @param offset
     * @param length
     * @return
     */

    public static byte[] wrapMessage (byte command, byte[] parameters, int offset, int length) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write((byte) 0x90);
        stream.write(command);
        stream.write((byte) 0x00);
        stream.write((byte) 0x00);
        if (parameters != null && length > 0) {
            // actually no length if empty length
            stream.write(length);
            stream.write(parameters, offset, length);
        }
        stream.write((byte) 0x00);
        return stream.toByteArray();
    }

    private String getHexString(byte[] a, boolean space) {
        if (a == null) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : a) {
            sb.append(String.format("%02x", b & 0xff));
            if (space) {
                sb.append(' ');
            }
        }
        return sb.toString().trim().toUpperCase();
    }

}
