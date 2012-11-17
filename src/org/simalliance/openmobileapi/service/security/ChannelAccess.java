/*
 * Copyright 2012 Giesecke & Devrient GmbH.
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

package org.simalliance.openmobileapi.service.security;


public class ChannelAccess {
    
    protected String CHANNEL_ACCESS_TAG = "ChannelAccess";
    
    protected String mPackageName = "";

    protected boolean mNoAccess = true;
    
    protected boolean mApduAccess = false;

    protected boolean mUseApduFilter = false;

    protected int mCallingPid = 0;

    protected String mReason = "no access by default";
    
    protected boolean mNFCEventAllowed = false;

    protected ApduFilter[] mApduFilter = null;
    
    public boolean isApduAccess() {
        return mApduAccess;
    }

    public void setApduAccess(boolean apduAccess) {
        this.mApduAccess = apduAccess;
    }


    public boolean isNoAccess() {
        return mNoAccess;
    }

    public void setNoAccess(boolean noAccess, String reason) {
        this.mNoAccess = noAccess;
        this.mReason = reason;
    }

    public boolean isUseApduFilter() {
        return mUseApduFilter;
    }

    public void setUseApduFilter(boolean useApduFilter) {
        this.mUseApduFilter = useApduFilter;
    }

    public void setCallingPid(int callingPid) {
        this.mCallingPid = callingPid;
    }

    public int getCallingPid() {
        return mCallingPid;
    }

    public String getReason() {
        return mReason;
    }
    public ApduFilter[] getApduFilter() {
        return mApduFilter;
    }

    public void setApduFilter(ApduFilter[] accessConditions) {
        mApduFilter = accessConditions;
    }
    public boolean isNFCEventAllowed() {
        return mNFCEventAllowed;
    }

    public void setNFCEventAllowed(boolean allowed) {
        this.mNFCEventAllowed = allowed;
    }
    
    public String toString(){
    	StringBuilder sb = new StringBuilder();
    	sb.append(this.getClass().getName());
    	sb.append("\n [mPackageName=");
    	sb.append(mPackageName);
    	sb.append(", mNoAccess=");
    	sb.append(mNoAccess);
    	sb.append(", mApduAccess=");
    	sb.append(mApduAccess);
    	sb.append(", mUseApduFilter=");
    	sb.append(mUseApduFilter);
    	sb.append(", mApduFilter=");
    	if( mApduFilter != null ){
	    	for( ApduFilter f : mApduFilter ){
	    		sb.append(f.toString());
	    		sb.append(" ");
	    	}
    	} else {
        	sb.append("null");
    	}
    	sb.append(", mCallingPid=");
    	sb.append(mCallingPid);
    	sb.append(", mReason=");
    	sb.append(mReason);
    	sb.append(", mNFCEventAllowed=");
    	sb.append(mNFCEventAllowed);
    	sb.append("]\n");
    	
    	return sb.toString();
    	
    }
}
