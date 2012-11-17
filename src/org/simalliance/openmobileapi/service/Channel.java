/*
 * Copyright (C) 2011, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Contributed by: Giesecke & Devrient GmbH.
 */

package org.simalliance.openmobileapi.service;


import java.security.AccessControlException;
import org.simalliance.openmobileapi.service.security.ChannelAccess;


import android.os.IBinder;
import android.os.RemoteException; 
import org.simalliance.openmobileapi.service.ISmartcardServiceCallback;
import android.util.Log;

/**
 * Smartcard service base class for channel resources.
 */
class Channel implements IChannel, IBinder.DeathRecipient {

    public static final String CHANNEL_TAG = "SmartcardService Channel";

    protected final int mChannelNumber;

    protected long mHandle;

    protected Terminal mTerminal;
    
    protected byte[] mSelectResponse;

    protected final IBinder mBinder;


    protected ChannelAccess mChannelAccess = null;
    protected int mCallingPid = 0;


    protected ISmartcardServiceCallback mCallback;

    protected boolean mHasSelectedAid = false;

    Channel(Terminal terminal, int channelNumber, ISmartcardServiceCallback callback) {
        this.mChannelNumber = channelNumber;
        this.mTerminal = terminal;
        this.mCallback = callback;
        this.mBinder = callback.asBinder();
        this.mSelectResponse = terminal.getSelectResponse();
        try {
            mBinder.linkToDeath(this, 0);
        } catch (RemoteException e) {
            Log.e(SmartcardService.SMARTCARD_SERVICE_TAG, "Failed to register client callback");
        }
    }

    public void binderDied() {
        // Close this channel if the client died.
        try {
            Log.v(SmartcardService.SMARTCARD_SERVICE_TAG, Thread.currentThread().getName()
                    + " Client " + mBinder.toString() + " died");
            close();
        } catch (Exception ignore) {
        }
    }

    public void close() throws CardException {
        try {
            getTerminal().closeChannel(this);
        } finally {
            mBinder.unlinkToDeath(this, 0);
        }
    }

    public int getChannelNumber() {
        return mChannelNumber;
    }

    /**
     * Returns if this channel is a basic channel
     * 
     * @return true if this channel is a basic channel
     */
    public boolean isBasicChannel() {
        return (mChannelNumber == 0) ? true : false;
    }

    public ISmartcardServiceCallback getCallback() {
        return mCallback;
    }

    /**
     * Returns the handle assigned to this channel.
     * 
     * @return the handle assigned to this channel.
     */
    long getHandle() {
        return mHandle;
    }

    /**
     * Returns the associated terminal.
     * 
     * @return the associated terminal.
     */
    public Terminal getTerminal() {
        return mTerminal;
    }

    /**
     * Assigns the channel handle.
     * 
     * @param handle the channel handle to be assigned.
     */
    void setHandle(long handle) {
        this.mHandle = handle;
    }

	public byte[] transmit(byte[] command) throws CardException {

		if( mChannelAccess == null ){
			throw new AccessControlException( " Channel access not set.");
		}
        if (mChannelAccess.getCallingPid() !=  mCallingPid) {



            throw new AccessControlException(" Wrong CallerUID. ");
        }



        checkCommand(command);


        if (command.length < 4) {
			throw new IllegalArgumentException(
					" command must not be smaller than 4 bytes");
		}
		if (((command[0] & (byte) 0x80) == 0)
				&& ((byte) (command[0] & (byte) 0x60) != (byte) 0x20)) {
			// ISO command
			if (command[1] == (byte) 0x70) {
				throw new IllegalArgumentException(
						"MANAGE CHANNEL command not allowed");
			}
			if ((command[1] == (byte) 0xA4) && (command[2] == (byte) 0x04)) {
				throw new IllegalArgumentException("SELECT command not allowed");
			}

		} else {
			// GlobalPlatform command
		}

		// set channel number bits
		command[0] = setChannelToClassByte(command[0], mChannelNumber);

		byte[] rsp = getTerminal().transmit(command, 2, 0, 0, null);
		return rsp;
	}
    
	/**
	 * Returns a copy of the given CLA byte where the channel number bits are
	 * set as specified by the given channel number
	 * 
	 * See GlobalPlatform Card Specification 2.2.0.7: 11.1.4 Class Byte Coding
	 * 
	 * @param cla
	 *            the CLA byte. Won't be modified
	 * @param channelNumber
	 *            within [0..3] (for first interindustry class byte coding) or
	 *            [4..19] (for further interindustry class byte coding)
	 * @return the CLA byte with set channel number bits. The seventh bit
	 *         indicating the used coding (first/further interindustry class
	 *         byte coding) might be modified
	 */
	private byte setChannelToClassByte(byte cla, int channelNumber) {
		if (channelNumber < 4) {
			// b7 = 0 indicates the first interindustry class byte coding
			cla = (byte) ((cla & 0xBC) | channelNumber);
		} else if (channelNumber < 20) {
			// b7 = 1 indicates the further interindustry class byte coding
			cla = (byte) ((cla & 0xB0) | 0x40 | (channelNumber - 4));
		} else {
			throw new IllegalArgumentException(
					"Channel number must be within [0..19]");
		}
		return cla;
	}


    public void setChannelAccess(ChannelAccess channelAccess) {
        this.mChannelAccess = channelAccess;
    }
    
    public ChannelAccess getChannelAccess(){
    	return this.mChannelAccess;
    }

    public void setCallingPid( int pid) {



    	mCallingPid = pid;
    }

    private void checkCommand( byte[] command ) {
	    if( getTerminal().getAccessController() != null ) { // re-use existing controller object for caching
	    	// check command if it complies to the access rules.
	    	// if not an exception is thrown
	    	getTerminal().getAccessController().checkCommand(this, command);
	    } else {
	    	throw new AccessControlException( "FATAL: Access Controller not set for Terminal: " + getTerminal().getName());
	    }
    }


    /**
     * @return
     */
    public boolean hasSelectedAid() {
        return mHasSelectedAid;
    }

    /**
     * @return
     */
    public void hasSelectedAid(boolean has) {
        mHasSelectedAid = has;
    }
    
    /**
     * Returns the data as received from the application select command inclusively the status word.
     * The returned byte array contains the data bytes in the following order:
     * [<first data byte>, ..., <last data byte>, <sw1>, <sw2>]
     * @return The data as returned by the application select command inclusively the status word.
     * @return Only the status word if the application select command has no returned data.
     * @return null if an application select command has not been performed or the selection response can not
     * be retrieved by the reader implementation.
     */
    public byte[] getSelectResponse()
    {
    	return mSelectResponse;
    }
}
