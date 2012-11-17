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

import org.simalliance.openmobileapi.service.ISmartcardServiceCallback;

import org.simalliance.openmobileapi.service.security.AccessController;
import org.simalliance.openmobileapi.service.security.ChannelAccess;
import android.content.pm.PackageManager;


/**
 * Smartcard service interface for terminal resources.
 */
public interface ITerminal {

    /**
     * Closes all open channels of this terminal.
     */
    void closeChannels();

    /**
     * Returns the channel for the specified handle or <code>null</code> if this
     * handle is not registered.
     * 
     * @param hChannel the channel handle.
     * @return the channel for the specified handle or <code>null</code> if this
     *         handle is not registered.
     */
    IChannel getChannel(long hChannel);

    /**
     * Returns the reader name.
     * 
     * @return the reader name.
     */
    String getName();

    /**
     * Sends a select command on the basic channel. With this command the
     * default application will be selected on the card. (e.g. CardManager)
     * 
     * @throw NoSuchElementException if the default applet couldn't be found or
     *        selected
     */
    public void select();

    /**
     * Sends a select command on the basic channel.
     * 
     * @param aid the aid which should be selected
     * @throw NoSuchElementException if the corresponding applet couldn't be
     *        found
     */
    public void select(byte[] aid);

    /**
     * Opens the basic channel to the card.
     * 
     * @param callback the callback used to react on the death of the client.
     * @return a handle for the basic channel.
     * @throws CardException if opening the basic channel failed or the basic
     *             channel is in use.
     */
    long openBasicChannel(ISmartcardServiceCallback callback) throws CardException;

    /**
     * Opens the basic channel to the card.
     * 
     * @param aid the AID of the applet to be selected.
     * @param callback the callback used to react on the death of the client.
     * @return a handle for the basic channel.
     * @throws CardException if opening the basic channel failed or the basic
     *             channel is in use.
     */
    long openBasicChannel(byte[] aid, ISmartcardServiceCallback callback) throws Exception;

    /**
     * Opens a logical channel to the card.
     * 
     * @param callback the callback used to react on the death of the client.
     * @return a handle for the logical channel.
     * @throws CardException if opening the logical channel failed.
     */
    long openLogicalChannel(ISmartcardServiceCallback callback) throws Exception;

    /**
     * Opens a logical channel to the card.
     * 
     * @param aid the AID of the applet to be selected.
     * @param callback the callback used to react on the death of the client.
     * @return a handle for the logical channel.
     * @throws CardException if opening the logical channel failed.
     */
    long openLogicalChannel(byte[] aid, ISmartcardServiceCallback callback) throws Exception;

    /**
     * Returns <code>true</code> if a card is present; <code>false</code>
     * otherwise.
     * 
     * @return <code>true</code> if a card is present; <code>false</code>
     *         otherwise.
     * @throws CardException if card presence information is not available.
     */
    boolean isCardPresent() throws CardException;

    /**
     * Returns <code>true</code> if terminal is connected <code>false</code>
     * otherwise.
     * 
     * @return <code>true</code> if at least one terminal is connected.
     */
    public boolean isConnected();

    /**
     * Returns the ATR of the connected card or null if the ATR is not
     * available.
     * 
     * @return the ATR of the connected card or null if the ATR is not
     *         available.
     */
    public byte[] getAtr();
    
    /**
     * Returns the data as received from the application select command inclusively the status word.
     * The returned byte array contains the data bytes in the following order:
     * [<first data byte>, ..., <last data byte>, <sw1>, <sw2>]
     * @return The data as returned by the application select command inclusively the status word.
     * @return Only the status word if the application select command has no returned data.
     * @return null if an application select command has not been performed or the selection response can not
     * be retrieved by the reader implementation.
     */
    public byte[] getSelectResponse();
	

    /**
     * Enables the Access Control Enforcer which reads the Access Rule from ARA (or ARF).
     * 
     * @return ChannelAccess object containing the access flags/filter.
     */
    ChannelAccess enableAccessConditions( PackageManager packageManager, byte[] aid, String[] packageNames, ISmartcardServiceCallback callback);
    AccessController getAccessController();
    	
}
