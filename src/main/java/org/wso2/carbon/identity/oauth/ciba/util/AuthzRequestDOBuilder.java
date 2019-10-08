package org.wso2.carbon.identity.oauth.ciba.util;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
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

    public AuthzRequestDTO buildAuthzRequestDO(JWT cibaAuthCodeasJWT, CibaAuthCodeDO cibaAuthCodeDO) throws NoSuchAlgorithmException, ParseException, IdentityOAuth2Exception, InvalidOAuthClientException {

        AuthzRequestDTO authzRequestDTO = new AuthzRequestDTO();

        JWTClaimsSet cibaAuthCodeJWTClaimsSet = cibaAuthCodeasJWT.getJWTClaimsSet();
        JSONObject jo = cibaAuthCodeJWTClaimsSet.toJSONObject();
        String clientID = String.valueOf(jo.get("aud"));
        String user = String.valueOf(jo.get("user_hint"));

        OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientID);
        //log.info(appDO.getCallbackUrl());

        String callbackUri = appDO.getCallbackUrl();

        authzRequestDTO.setAuthReqIDasState(cibaAuthCodeDO.getCibaAuthCodeID());
        authzRequestDTO.setCallBackUrl(callbackUri);
        authzRequestDTO.setUser(user);
        authzRequestDTO.setClient_id(clientID);


        return authzRequestDTO;
    }


}
