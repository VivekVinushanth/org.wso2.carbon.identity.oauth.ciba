package org.wso2.carbon.identity.oauth.ciba.model;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

public class CibaAuthCodeDO {

    public CibaAuthCodeDO(){}

    private String cibaAuthCodeID;
    private String cibaAuthCode;
    private String hashedCibaAuthCode;
    private String  authenticationStatus;
    private String  authenticatedUser;
    private long lastPolledTime;
    private long interval;


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



}
