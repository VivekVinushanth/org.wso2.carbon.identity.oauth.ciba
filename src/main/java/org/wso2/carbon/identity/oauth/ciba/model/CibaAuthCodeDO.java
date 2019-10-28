/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */


package org.wso2.carbon.identity.oauth.ciba.model;

public class CibaAuthCodeDO {

    public CibaAuthCodeDO(){}

    private String cibaAuthCodeID;
    private String cibaAuthCode;
    private String hashedCibaAuthCode;
    private String  authenticationStatus;
    private String  authenticatedUser;
    private long lastPolledTime;
    private long interval;
    private long expiryTime;
    private String bindingMessage;
    private String transactionContext;
    private String scope;



    public String getCibaAuthCodeID() {
        return cibaAuthCodeID;
    }

    public void setCibaAuthCodeID(String cibaAuthCodeID) {
        this.cibaAuthCodeID = cibaAuthCodeID;
    }

    public String getCibaAuthCode() {
        return cibaAuthCode;
    }

    public void setCibaAuthCode(String cibaAuthCode) {
        this.cibaAuthCode = cibaAuthCode;
    }

    public String getHashedCibaAuthCode() {
        return hashedCibaAuthCode;
    }

    public void setHashedCibaAuthCode(String hashedCibaAuthCode) {
        this.hashedCibaAuthCode = hashedCibaAuthCode;
    }


    public String getAuthenticationStatus() {
        return authenticationStatus;
    }

    public void setAuthenticationStatus(String  authenticationStatus) {
        this.authenticationStatus = authenticationStatus;
    }

    public String getAuthenticatedUser() {
        return authenticatedUser;
    }

    public void setAuthenticatedUser(String  authenticatedUser) {
        this.authenticatedUser = authenticatedUser;
    }


    public void setExpiryTime(long expiryTime) {
        this.expiryTime = expiryTime;
    }

    public long getExpiryTime() {
        return expiryTime;
    }

    public String getBindingMessage() {
        return bindingMessage;
    }

    public void setBindingMessage(String bindingMessage) {
        this.bindingMessage = bindingMessage;
    }

    public String getTransactionContext() {
        return transactionContext;
    }

    public void setTransactionContext(String transactionContext) {
        this.transactionContext = transactionContext;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }


    public long getLastPolledTime() {
        return lastPolledTime;
    }

    public void setLastPolledTime(long lastPolledTime) {
        this.lastPolledTime = lastPolledTime;
    }


    public long getInterval() {
        return interval;
    }

    public void setInterval(long interval) {
        this.interval = interval;
    }

}
