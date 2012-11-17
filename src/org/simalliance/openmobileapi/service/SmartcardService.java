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

import dalvik.system.DexClassLoader;
import dalvik.system.DexFile;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.RemoteException; 
import org.simalliance.openmobileapi.service.ISmartcardService;
import org.simalliance.openmobileapi.service.ISmartcardServiceCallback;
import android.util.Log;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.security.AccessControlException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.TreeMap;



import org.simalliance.openmobileapi.service.security.AccessController;
import org.simalliance.openmobileapi.service.security.ChannelAccess;


/**
 * The smartcard service is setup with privileges to access smart card hardware.
 * The service enforces the permission
 * 'org.simalliance.openmobileapi.service.permission.BIND'.
 */
public final class SmartcardService extends Service {

    public static final String SMARTCARD_SERVICE_TAG = "SmartcardService";
    
    static void clearError(SmartcardError error) {
        if (error != null) {
            error.clear();
        }
    }

    @SuppressWarnings("unchecked")
    static void setError(SmartcardError error, Class clazz, String message) {
        if (error != null) {
            error.setError(clazz, message);
        }
    }

    private static void setError(SmartcardError error, Exception e) {
        if (error != null) {
            error.setError(e.getClass(), e.getMessage());
        }
    }

    /**
     * For now this list is setup in onCreate(), not changed later and therefore
     * not synchronized.
     */
    private Map<String, ITerminal> mTerminals = new TreeMap<String, ITerminal>();

    /**
     * For now this list is setup in onCreate(), not changed later and therefore
     * not synchronized.
     */
    private Map<String, ITerminal> mAddOnTerminals = new TreeMap<String, ITerminal>();


    /**
     * The smartcard service interface implementation.
     */
    private final ISmartcardService.Stub mSmartcardBinder = new ISmartcardService.Stub() {

        public void closeChannel(long hChannel, SmartcardError error) throws RemoteException {
            clearError(error);
            IChannel channel = getChannel(hChannel, error);
            if (channel == null) {
                return;
            }
        	
            ITerminal terminal = channel.getTerminal();
            if( terminal == null ){
            	return;
            }

            if (channel.isBasicChannel() && channel.hasSelectedAid()) {
                try {
                    terminal.select();
                } catch (NoSuchElementException exp) {

                    // Selection of the default application fails
                    try {
                    	AccessController access = channel.getTerminal().getAccessController();
                    	if( access != null ){
                    		terminal.select(AccessController.getDefaultAccessControlAid());
                    	}
                    } catch (NoSuchElementException exp2) {
                        // Access Control Applet not available => Don't care
                    }

                }
            }

            try {
                channel.close();
            } catch (Exception e) {
                setError(error, e);
            }
        }

        public String[] getReaders(SmartcardError error) throws RemoteException {
            clearError(error);
            
            Log.v(SMARTCARD_SERVICE_TAG, "getReaders()"); 

            return updateTerminals();
        }

        public byte[] getAtr(String reader, SmartcardError error) throws RemoteException {
            clearError(error);
            ITerminal terminal = getTerminal(reader, error);
            if (terminal == null) {
                return null;
            }
            try {
                byte[] atr = terminal.getAtr();
                return atr;
            } catch (Exception e) {
                setError(error, e);
                return null;
            }
        }

        public boolean isCardPresent(String reader, SmartcardError error) throws RemoteException {
            clearError(error);
            ITerminal terminal = getTerminal(reader, error);
            if (terminal == null) {
                return false;
            }
            try {
                boolean isPresent = terminal.isCardPresent();
                return isPresent;
            } catch (Exception e) {
                setError(error, e);
                return false;
            }
        }

        public long openBasicChannel(String reader, ISmartcardServiceCallback callback,
                SmartcardError error) throws RemoteException {

            return openBasicChannelAid(reader, null, callback, error);
        }

        public long openBasicChannelAid(String reader, byte[] aid,
                ISmartcardServiceCallback callback, SmartcardError error) throws RemoteException {
            clearError(error);
            if (callback == null) {
                setError(error, NullPointerException.class, "callback must not be null");
                return 0;
            }
            ITerminal terminal = getTerminal(reader, error);
            if (terminal == null) {
            	// if terminal is null then error is already set in 
            	// getTerminal().
                return 0;
            }

            try {

                boolean noAid = false;
                if (aid == null || aid.length == 0) {
                    aid = new byte[] {
                            0x00, 0x00, 0x00, 0x00, 0x00
                    };
                    noAid = true;
                }

                if (aid.length < 5 || aid.length > 16) {
                    setError(error, IllegalArgumentException.class, "AID out of range");
                    return 0;
                }


                String[] processNames = new String[]{ getProcessNameFromPid(Binder.getCallingPid())};
                Log.v(SMARTCARD_SERVICE_TAG, "Enable access control on basic channel.");
                ChannelAccess channelAccess = terminal.enableAccessConditions(
                		getPackageManager(), 
                		aid,
                        processNames, 
                        callback );
                Log.v(SMARTCARD_SERVICE_TAG, "Access control successfully enabled.");
                
                channelAccess.setCallingPid(Binder.getCallingPid());


                Log.v(SMARTCARD_SERVICE_TAG, "OpenBasicChannel(AID)");
                long hChannel = 0;
                if (noAid) {
                    hChannel = terminal.openBasicChannel(callback);
                } else {
                    hChannel = terminal.openBasicChannel(aid, callback);
                }
                IChannel channel = getChannel(hChannel, error);

                channel.setChannelAccess(channelAccess);

                Log.v(SMARTCARD_SERVICE_TAG, "Open basic channel success. Channel: " + channel.getChannelNumber() );
                return hChannel;
            } catch (Exception e) {
                setError(error, e);
                Log.v(SMARTCARD_SERVICE_TAG, "OpenBasicChannel Exception: " + e.getMessage());
                return 0;
            }
        }

        public long openLogicalChannel(String reader, byte[] aid,
                ISmartcardServiceCallback callback, SmartcardError error) throws RemoteException {
            clearError(error);

            if (callback == null) {
                setError(error, NullPointerException.class, "callback must not be null");
                return 0;
            }
            ITerminal terminal = getTerminal(reader, error);
            if (terminal == null) {
            	// if terminal is null then error is already set in 
            	// getTerminal().
                return 0;
            }

            try {

                boolean noAid = false;
                if (aid == null || aid.length == 0) {
                    aid = new byte[] {
                            0x00, 0x00, 0x00, 0x00, 0x00
                    };
                    noAid = true;
                }

                if (aid.length < 5 || aid.length > 16) {
                    setError(error, IllegalArgumentException.class, "AID out of range");
                    return 0;
                }


                String[] processNames = new String[]{getProcessNameFromPid(Binder.getCallingPid())};
                Log.v(SMARTCARD_SERVICE_TAG, "Enable access control on logical channel.");
                ChannelAccess channelAccess = terminal.enableAccessConditions(
                		getPackageManager(), 
                		aid,
                        processNames, 
                        callback );
                Log.v(SMARTCARD_SERVICE_TAG, "Access control successfully enabled.");
                
                channelAccess.setCallingPid(Binder.getCallingPid());

                Log.v(SMARTCARD_SERVICE_TAG, "OpenLogicalChannel");
                long hChannel = 0;
                if (noAid) {
                    hChannel = terminal.openLogicalChannel(callback);
                } else {
                    hChannel = terminal.openLogicalChannel(aid, callback);
                }
                IChannel channel = getChannel(hChannel, error);

                channel.setChannelAccess(channelAccess);

                Log.v(SMARTCARD_SERVICE_TAG, "Open logical channel successfull. Channel: " + channel.getChannelNumber());
                return hChannel;
            } catch (Exception e) {
                setError(error, e);
                Log.v(SMARTCARD_SERVICE_TAG, "OpenLogicalChannel Exception: " + e.getMessage());
                return 0;
            }
        }

        public byte[] transmit(long hChannel, byte[] command, SmartcardError error)
                throws RemoteException {
            clearError(error);

            try {
                if (command == null) {
                    setError(error, NullPointerException.class, "command must not be null");
                    return null;
                }
                if (command.length < 4) {
                    setError(error, IllegalArgumentException.class,
                            "command must have at least 4 bytes");
                    return null;
                }
                IChannel channel = getChannel(hChannel, error);
                if (channel == null) {
                    return null;
                }

                channel.setCallingPid(Binder.getCallingPid());


                byte[] response = channel.transmit(command);

                return response;
            } catch (Exception e) {
                Log.v(SMARTCARD_SERVICE_TAG, "transmit Exception: " + e.getMessage() + " (Command: " + Util.bytesToString(command) + ")");
                setError(error, e);
                return null;
            }
        }
        public byte[] getSelectResponse(long hChannel, SmartcardError error)
        	 throws RemoteException {
        	clearError(error);
        	try {
                IChannel channel = getChannel(hChannel, error);
                if (channel == null) {
                    return null;
                }
                byte[] selectResponse = channel.getSelectResponse();
        		return selectResponse;
             } catch (Exception e) {
                 setError(error, e);
                 Log.v(SMARTCARD_SERVICE_TAG, "getSelectResponse Exception: " + e.getMessage() );
                 return null;
             }
        }
	        
        public boolean[] isNFCEventAllowed(String reader, byte[] aid,
                String[] packageNames, ISmartcardServiceCallback callback, SmartcardError error) throws RemoteException
        {
            try
            {
                if (callback == null) {
                    setError(error, NullPointerException.class, "callback must not be null");
                    return null;
                }
                ITerminal terminal = getTerminal(reader, error);
                if (terminal == null) {
                    return null;
                }
                if (aid == null || aid.length == 0) {
                    aid = new byte[] {
                            0x00, 0x00, 0x00, 0x00, 0x00
                    };
                }
                if (aid.length < 5 || aid.length > 16) {
                     setError(error, IllegalArgumentException.class, "AID out of range");
                     return null;
                }
                if (packageNames == null || packageNames.length == 0) {
                     setError(error, IllegalArgumentException.class, "process names not specified");
                     return null;
                }
	            AccessController ac = new AccessController(getPackageManager());
	            return ac.isNFCEventAllowed(terminal, aid, packageNames, callback );
            } catch (Exception e) {
                setError(error, e);
                Log.v(SMARTCARD_SERVICE_TAG, "isNFCEventAllowed Exception: " + e.getMessage() );
                return null;
            }
        }
    };

    public SmartcardService() {
        super();
    }

    @Override
    public IBinder onBind(Intent intent) {
        Log.v(SMARTCARD_SERVICE_TAG, Thread.currentThread().getName()
                        + " smartcard service onBind");
        if (ISmartcardService.class.getName().equals(intent.getAction())) {
            return mSmartcardBinder;
        }
        return null;
    }

    @Override
    public void onCreate() {
        Log.v(SMARTCARD_SERVICE_TAG, Thread.currentThread().getName()
                + " smartcard service onCreate");
        createTerminals();
    }

    @Override
    public void onDestroy() {
        Log.v(SMARTCARD_SERVICE_TAG, Thread.currentThread().getName()
                + " smartcard service onDestroy ...");
        for (ITerminal terminal : mTerminals.values())
            terminal.closeChannels();
        for (ITerminal terminal : mAddOnTerminals.values())
            terminal.closeChannels();

        Log.v(SMARTCARD_SERVICE_TAG, Thread.currentThread().getName()
                + " ... smartcard service onDestroy");
    }

    private IChannel getChannel(long hChannel, SmartcardError error) {
        for (ITerminal terminal : mTerminals.values()) {
            IChannel channel = terminal.getChannel(hChannel);
            if (channel != null) {
                return channel;
            }
        }
        for (ITerminal terminal : mAddOnTerminals.values()) {
            IChannel channel = terminal.getChannel(hChannel);
            if (channel != null) {
                return channel;
            }
        }
        setError(error, IllegalArgumentException.class, "invalid handle");
        return null;
    }

    private ITerminal getTerminal(String reader, SmartcardError error) {
        if (reader == null) {
            setError(error, NullPointerException.class, "reader must not be null");
            return null;
        }
        ITerminal terminal = mTerminals.get(reader);
        if (terminal == null) {

            terminal = mAddOnTerminals.get(reader);
            if (terminal == null) {
                setError(error, IllegalArgumentException.class, "unknown reader");
            }
        }
        return terminal;
    }

    private String[] createTerminals() {
        createBuildinTerminals();

        Set<String> names = mTerminals.keySet();
        ArrayList<String> list = new ArrayList<String>(names);
        Collections.sort(list);
        
        // set UICC on the top
        if(list.remove("SIM: UICC")) 
        	list.add(0, "SIM: UICC");

        createAddonTerminals();
        names = mAddOnTerminals.keySet();
        for (String name : names) {
            if (!list.contains(name)) {
                list.add(name);
            }
        }
        
        return list.toArray(new String[list.size()]);
    }

    private String[] updateTerminals() {
        Set<String> names = mTerminals.keySet();
        ArrayList<String> list = new ArrayList<String>(names);
        Collections.sort(list);
        
        // set UICC on the top
        if(list.remove("SIM: UICC")) 
        	list.add(0, "SIM: UICC");
        
        updateAddonTerminals();
        names = mAddOnTerminals.keySet();
        for (String name : names) {
            if (!list.contains(name)) {
                list.add(name);
            }
        }
        
        return list.toArray(new String[list.size()]);
    }

    private void createBuildinTerminals() {
        Class[] types = new Class[] {
            Context.class
        };
        Object[] args = new Object[] {
            this
        };
        Object[] classes = getBuildinTerminalClasses();
        for (Object clazzO : classes) {
            try {
                Class clazz = (Class) clazzO;
                Constructor constr = clazz.getDeclaredConstructor(types);
                ITerminal terminal = (ITerminal) constr.newInstance(args);
                mTerminals.put(terminal.getName(), terminal);
                Log.v(SMARTCARD_SERVICE_TAG, Thread.currentThread().getName() + " adding "
                        + terminal.getName());
            } catch (Throwable t) {
                Log.e(SMARTCARD_SERVICE_TAG, Thread.currentThread().getName()
                        + " CreateReaders Error: "
                        + ((t.getMessage() != null) ? t.getMessage() : "unknown"));
            }
        }
    }

    private void createAddonTerminals() {
        String[] packageNames = AddonTerminal.getPackageNames(this);
        for (String packageName : packageNames) {
            try {
                String apkName = getPackageManager().getApplicationInfo(packageName, 0).sourceDir;
                DexFile dexFile = new DexFile(apkName);
                Enumeration<String> classFileNames = dexFile.entries();
                while (classFileNames.hasMoreElements()) {
                    String className = classFileNames.nextElement();
                    if (className.endsWith("Terminal")) {
                        ITerminal terminal = new AddonTerminal(this, packageName, className);
                        mAddOnTerminals.put(terminal.getName(), terminal);
                        Log.v(SMARTCARD_SERVICE_TAG, Thread.currentThread().getName() + " adding "
                                + terminal.getName());
                    }
                }
            } catch (Throwable t) {
                Log.e(SMARTCARD_SERVICE_TAG, Thread.currentThread().getName()
                        + " CreateReaders Error: "
                        + ((t.getMessage() != null) ? t.getMessage() : "unknown"));
            }
        }
    }

    private void updateAddonTerminals() {
        Set<String> names = mAddOnTerminals.keySet();
        ArrayList<String> namesToRemove = new ArrayList<String>();
        for (String name : names) {
            ITerminal terminal = mAddOnTerminals.get(name);
            if (!terminal.isConnected()) {
                namesToRemove.add(terminal.getName());
            }
        }
        for (String name : namesToRemove) {
            mAddOnTerminals.remove(name);
        }

        String[] packageNames = AddonTerminal.getPackageNames(this);
        for (String packageName : packageNames) {
            try {
                String apkName = getPackageManager().getApplicationInfo(packageName, 0).sourceDir;
                DexFile dexFile = new DexFile(apkName);
                Enumeration<String> classFileNames = dexFile.entries();
                while (classFileNames.hasMoreElements()) {
                    String className = classFileNames.nextElement();
                    if (className.endsWith("Terminal")) {
                        ITerminal terminal = new AddonTerminal(this, packageName, className);
                        if (!mAddOnTerminals.containsKey(terminal.getName())) {
                            mAddOnTerminals.put(terminal.getName(), terminal);
                            Log.v(SMARTCARD_SERVICE_TAG, Thread.currentThread().getName()
                                    + " adding " + terminal.getName());
                        }
                    }
                }

            } catch (Throwable t) {
                Log.e(SMARTCARD_SERVICE_TAG, Thread.currentThread().getName()
                        + " CreateReaders Error: "
                        + ((t.getMessage() != null) ? t.getMessage() : "unknown"));
            }
        }
    }

    private Object[] getBuildinTerminalClasses() {
        ArrayList classes = new ArrayList();
        try {
            String packageName = "org.simalliance.openmobileapi.service";
            String apkName = getPackageManager().getApplicationInfo(packageName, 0).sourceDir;
            DexClassLoader dexClassLoader = new DexClassLoader(apkName, getApplicationContext().getFilesDir().getAbsolutePath(), null, getClass()
                    .getClassLoader());

            Class terminalClass = Class.forName("org.simalliance.openmobileapi.service.Terminal", true, dexClassLoader);
            if (terminalClass == null) {
                return classes.toArray();
            }

            DexFile dexFile = new DexFile(apkName);
            Enumeration<String> classFileNames = dexFile.entries();
            while (classFileNames.hasMoreElements()) {
                String className = classFileNames.nextElement();
                Class clazz = Class.forName(className);
                Class superClass = clazz.getSuperclass();
                if (superClass != null && superClass.equals(terminalClass)
                        && !className.equals("org.simalliance.openmobileapi.service.AddonTerminal")) {
                    classes.add(clazz);
                }
            }
        } catch (Throwable exp) {
            // nothing to to
        }

        return classes.toArray();
    }

    public String getProcessNameFromPid(int pid) {
        ActivityManager am = (ActivityManager) getSystemService(Activity.ACTIVITY_SERVICE);
        List<ActivityManager.RunningAppProcessInfo> appInfoList = am.getRunningAppProcesses();
        for (ActivityManager.RunningAppProcessInfo appInfo : appInfoList) {
            if (appInfo.pid == pid) {
                return appInfo.processName;
            }

        }
        throw new AccessControlException("CallerPackageName can not be determined");
    }

}
