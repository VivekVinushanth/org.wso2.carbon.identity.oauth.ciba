package org.wso2.carbon.identity.oauth.ciba.common;

/**
 * This class is meant to store the features of the transaction.
 * */
public class CibaConstants {



    public static long expires_in = 3600;
    public static long interval=2;

    public static final String EXPIRES_IN = "expires_in";
    public static final  String INTERVAL = "interval";
    public static final String AUTH_REQ_ID = "auth_req_id";
    public static final String REQUEST = "request";


    public static final String OAUTH_CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba";
    public static final String AUTHORIZE_ENDPOINT = "https://localhost:9443/oauth2/authorize";
    public static final String RESPONSE_TYPE = "ciba";

    private CibaConstants() {

    }
}
