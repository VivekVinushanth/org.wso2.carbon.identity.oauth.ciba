package org.wso2.carbon.identity.oauth.ciba.dto;

public class AuthzRequestDTO {
    private String user;
    private String authReqIDasState;
    private String client_id;
    private String callBackUrl;

    public String getCallBackUrl() {
        return callBackUrl;
    }

    public void setCallBackUrl(String callBackUrl) {
        this.callBackUrl = callBackUrl;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getAuthReqIDasState() {
        return authReqIDasState;
    }

    public void setAuthReqIDasState(String authReqIDasState) {
        this.authReqIDasState = authReqIDasState;
    }

    public String getClient_id() {
        return client_id;
    }

    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }


}
