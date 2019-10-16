package org.wso2.carbon.identity.oauth.ciba.util;


import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.security.NoSuchAlgorithmException;
import java.text.ParseException;

public class AuthzRequestDOBuilder {

    private static final Log log = LogFactory.getLog(AuthzRequestDOBuilder.class);
    private AuthzRequestDOBuilder() {

    }

    private static AuthzRequestDOBuilder AuthzRequestDOBuilderInstance = new AuthzRequestDOBuilder();

    public static AuthzRequestDOBuilder getInstance() {
        if (AuthzRequestDOBuilderInstance == null) {

            synchronized (AuthzRequestDOBuilder.class) {

                if (AuthzRequestDOBuilderInstance == null) {

                    /* instance will be created at request time */
                    AuthzRequestDOBuilderInstance = new AuthzRequestDOBuilder();
                }
            }
        }
        return AuthzRequestDOBuilderInstance;


    }

    public AuthzRequestDTO buildAuthzRequestDO(CibaAuthRequestDTO cibaAuthRequestDTO, CibaAuthCodeDO cibaAuthCodeDO) throws NoSuchAlgorithmException, ParseException, IdentityOAuth2Exception, InvalidOAuthClientException {

        AuthzRequestDTO authzRequestDTO = new AuthzRequestDTO();

        String clientID = cibaAuthRequestDTO.getAudience();
        String user = cibaAuthRequestDTO.getUserHint();

        OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientID);
        //log.info(appDO.getCallbackUrl());

        String callbackUri = appDO.getCallbackUrl();

        authzRequestDTO.setAuthReqIDasState(cibaAuthCodeDO.getCibaAuthCodeID());
        authzRequestDTO.setCallBackUrl(callbackUri);
        authzRequestDTO.setUser(user);
        authzRequestDTO.setClient_id(clientID);
        authzRequestDTO.setBindingMessage(cibaAuthCodeDO.getBindingMessage());
        authzRequestDTO.setTransactionDetails(cibaAuthCodeDO.getTransactionContext());
        authzRequestDTO.setScope(cibaAuthCodeDO.getScope());

        return authzRequestDTO;
    }


}
