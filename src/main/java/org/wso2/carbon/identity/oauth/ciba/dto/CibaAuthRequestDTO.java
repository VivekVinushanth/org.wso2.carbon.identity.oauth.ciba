package org.wso2.carbon.identity.oauth.ciba.dto;

public class CibaAuthRequestDTO {


    private String issuer;
    private String audience;
    private long issuedTime;
    private long expiredTime;
    private long notBeforeTime;
    private String JWTID;

    private long requestedExpiry;
    private String userHint;
    private String bindingMessage;
    private String userCode;
    private String scope ;
    private String clientNotificationToken;
    private String acrValues;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public long getIssuedTime() {
        return issuedTime;
    }

    public void setIssuedTime(long issuedTime) {
        this.issuedTime = issuedTime;
    }

    public long getExpiredTime() {
        return expiredTime;
    }

    public void setExpiredTime(long expiredTime) {
        this.expiredTime = expiredTime;
    }

    public long getNotBeforeTime() {
        return notBeforeTime;
    }

    public void setNotBeforeTime(long notBeforeTime) {
        this.notBeforeTime = notBeforeTime;
    }

    public String getJWTID() {
        return JWTID;
    }

    public void setJWTID(String JWTID) {
        this.JWTID = JWTID;
    }

    public long getRequestedExpiry() {
        return requestedExpiry;
    }

    public void setRequestedExpiry(long requestedExpiry) {
        this.requestedExpiry = requestedExpiry;
    }

    public String getUserHint() {
        return userHint;
    }

    public void setUserHint(String userHint) {
        this.userHint = userHint;
    }

    public String getBindingMessage() {
        return bindingMessage;
    }

    public void setBindingMessage(String bindingMessage) {
        this.bindingMessage = bindingMessage;
    }

    public String getUserCode() {
        return userCode;
    }

    public void setUserCode(String userCode) {
        this.userCode = userCode;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getClientNotificationToken() {
        return clientNotificationToken;
    }

    public void setClientNotificationToken(String clientNotificationToken) {
        this.clientNotificationToken = clientNotificationToken;
    }

    public String getAcrValues() {
        return acrValues;
    }

    public void setAcrValues(String acrValues) {
        this.acrValues = acrValues;
    }



}
