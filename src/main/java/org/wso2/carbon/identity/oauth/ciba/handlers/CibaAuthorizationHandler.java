package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.web.client.RestTemplate;


public class CibaAuthorizationHandler implements Handler {

private static final String CLIENT_ID="client_id";
private static final String STATE_PARAMATER = "state";
private static final String USER_IDENTITY = "user";

    private static final Log log = LogFactory.getLog(CibaAuthorizationHandler.class);
    private CibaAuthorizationHandler() {

    }

    private static CibaAuthorizationHandler CibaAuthorizationHandlerInstance = new CibaAuthorizationHandler();

    public static CibaAuthorizationHandler getInstance() {
        if (CibaAuthorizationHandlerInstance == null) {

            synchronized (CibaAuthorizationHandler.class) {

                if (CibaAuthorizationHandlerInstance == null) {

                    /* instance will be created at request time */
                    CibaAuthorizationHandlerInstance = new CibaAuthorizationHandler();
                }
            }
        }
        return CibaAuthorizationHandlerInstance;


    }

    public void initiateAuthzRequest(AuthzRequestDTO authzRequestDto){

        RestTemplate restTemplate = new RestTemplate();

        String result = restTemplate.getForObject(CibaConstants.AUTHORIZE_ENDPOINT+"?scope=openid&" +
                "response_type=ciba&state=" + authzRequestDto.getAuthReqIDasState() + "&redirect_uri=" +
                authzRequestDto.getCallBackUrl() + "&client_id=" + authzRequestDto.getClient_id() + "&user=" + authzRequestDto.getUser(), String.class);

    }


}
