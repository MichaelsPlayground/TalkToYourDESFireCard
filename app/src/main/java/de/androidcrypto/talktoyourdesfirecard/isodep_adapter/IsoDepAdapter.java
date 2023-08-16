package de.androidcrypto.talktoyourdesfirecard.isodep_adapter;

public interface IsoDepAdapter extends IsoDepWrapper {

    byte[] sendCommandChain(byte command, byte[] parameters, int offset, int length) throws Exception;

    byte[] sendCommandChain(byte command, byte[] parameters) throws Exception;

    byte[] sendCommand(byte command, byte[] parameters, int offset, int length, byte expect) throws Exception;

    byte[] sendCommand(byte command, byte[] parameters, byte expect) throws Exception;

    byte[] sendAdpuChain(byte[] adpu) throws Exception;

}
