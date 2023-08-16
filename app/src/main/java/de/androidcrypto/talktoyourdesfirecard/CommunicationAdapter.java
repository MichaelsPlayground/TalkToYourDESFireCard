package de.androidcrypto.talktoyourdesfirecard;

import android.nfc.tech.IsoDep;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import de.androidcrypto.talktoyourdesfirecard.isodep_adapter.IsoDepWrapper;

/**
 * this class is responsible for sending to and receiving of data from the DESFire tag. As the size
 * is limited the commands need to get chunked and the response could be split into several parts.
 */

public class CommunicationAdapter {

    private static final String TAG = CommunicationAdapter.class.getName();
    private final boolean logging = true;

    // constants
    public static final byte OPERATION_OK = (byte)0x00;
    public static final byte ADDITIONAL_FRAME = (byte)0xAF;
    public static final byte GET_ADDITIONAL_FRAME      = (byte) 0xAF;

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
    private boolean debug = true;
    private byte statusCode, errorCode;
    private String statusCodeName, errorCodeName;

    public CommunicationAdapter(IsoDep isoDep, boolean print) {
        this.isoDep = isoDep;
        this.print = print;
    }

    public byte[] transceive(byte[] request) throws IOException {

        if(logging) {
            Log.d(TAG, "===> " + Utils.bytesToHex(request) + " (" + request.length + ")");
        }

        byte[] response = isoDep.transceive(request);

        if(logging) {
            Log.d(TAG, "<=== " + Utils.bytesToHex(response) + " (" + request.length + ")");
        }

        return response;
    }

    /*
    public byte[] sendCommandChain(byte command, byte[] parameters, int offset, int length) throws Exception {
        return sendAdpuChain(wrapMessage(command, parameters, offset, length));
    }*/

    public byte[] sendCommandChain(byte command, byte[] parameters, int offset, int length) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        int count = 0;

        byte nextCommand = command;
        while(true) {

            int nextLength = Math.min(MAX_CAPDU_SIZE - 1, length - count);

            byte[] request = wrapMessage(nextCommand, parameters, offset + count, nextLength);

            byte[] response = transceive(request);

            count += nextLength;

            if (response[response.length - 2] != (byte) 0x91) {
                throw new Exception("Invalid response " + String.format("%02x", response[response.length - 2] & 0xff));
            }

            output.write(response, 0, response.length - 2);

            byte status = response[response.length - 1];
            if (status == OPERATION_OK) {
                if(count != length) {
                    throw new IllegalArgumentException("Expected sent " + length + " bytes but was " + count);
                }
                break;
            } else if (status == ADDITIONAL_FRAME) {
                nextCommand = ADDITIONAL_FRAME;
            } else {
                throw new Exception("PICC error code: " + Integer.toHexString(status & 0xFF));
            }
        }
        return output.toByteArray();
    }

    /**
     * This is the all in one solution - wrapping outgoing and incoming data
     * @param apdu
     * @return
     * @throws Exception
     */
    public byte[] sendAdpuChain(byte[] apdu) throws Exception {
        return readAdpuChain(writeAdpuChain(apdu));
    }

    public byte[] sendCommand(byte command, byte[] parameters, int offset, int length, byte expected) throws Exception {
        byte[] request = wrapMessage(command, parameters, offset, length);

        byte[] response = transceive(request);

        if (response[response.length - 2] != (byte) 0x91) {
            throw new Exception("Invalid response " + String.format("%02x", response[response.length - 2] & 0xff));
        }

        byte status = response[response.length - 1];
        if (status != expected) {
            throw new Exception("Expected " + Integer.toHexString(expected & 0xFF) + ", got " + Integer.toHexString(status & 0xFF));
        }

        byte[] data = new byte[response.length -2];
        System.arraycopy(response, 0, data, 0, data.length);
        return data;
    }


    public byte[] sendCommandChain(byte command, byte[] parameters) throws Exception {
        return sendCommandChain(command, parameters, 0, parameters != null ? parameters.length : 0);
    }


    public byte[] sendCommand(byte command, byte[] parameters, byte expected) throws Exception {
        return sendCommand(command, parameters, 0, parameters != null ? parameters.length : 0, expected);
    }

    public byte[] writeAdpuChain(byte[] response) throws Exception {

        if(response[response.length - 2] == OPERATION_OK && response[response.length - 1] == OPERATION_OK) {
            return response;
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        do {
            if (response[response.length - 2] != OPERATION_OK) {
                // todo remove this
                System.out.println("*** Invalid response ***");
                System.out.println(Utils.bytesToHex(response));

                // todo remove comment
                //throw new Exception("Invalid response " + String.format("%02x", response[response.length - 2] & 0xff));
            }

            output.write(response, 0, response.length - 2);

            byte status = response[response.length - 1];
            if (status == OPERATION_OK) {
                return output.toByteArray();
            } else if (status != ADDITIONAL_FRAME) {
                throw new Exception("PICC error code while reading response: " + Integer.toHexString(status & 0xFF));
            }

            response = transceive(wrapMessage(ADDITIONAL_FRAME));
        } while(true);
    }

    public byte[] readAdpuChain(byte[] apdu) throws Exception {

        if(apdu.length <= MAX_CAPDU_SIZE) {
            return transceive(apdu);
        }
        int offset = 5; // data area of apdu

        byte nextCommand =  apdu[1];
        while(true) {
            int nextLength = Math.min(MAX_CAPDU_SIZE - 1, apdu.length - offset);

            byte[] request = wrapMessage(nextCommand, apdu, offset, nextLength);

            byte[] response = transceive(request);
            if (response[response.length - 2] != OPERATION_OK) {
                throw new Exception("Invalid response " + String.format("%02x", response[response.length - 2] & 0xff));
            }

            offset += nextLength;
            if(offset == apdu.length) {
                return response;
            }

            if(response.length != 2) {
                throw new IllegalArgumentException("Expected empty response payload while transmitting request");
            }
            byte status = response[response.length - 1];
            if (status != ADDITIONAL_FRAME) {
                throw new Exception("PICC error code: " + Integer.toHexString(status & 0xFF));
            }
            nextCommand = ADDITIONAL_FRAME;
        }

    }



    public static byte[] wrapMessage (byte command) throws Exception {
        return new byte[]{(byte) 0x90, command, 0x00, 0x00, 0x00};
    }

    public static byte[] wrapMessage (byte command, byte[] parameters, int offset, int length) throws Exception {
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




}
