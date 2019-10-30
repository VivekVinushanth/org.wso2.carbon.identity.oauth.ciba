package org.wso2.carbon.identity.oauth.ciba.util;

import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletResponse;

public class AuthzRequestDTOGenerator {

    private static final Log log = LogFactory.getLog(AuthzRequestDTOGenerator.class);

    private AuthzRequestDTOGenerator() {

    }

    private static AuthzRequestDTOGenerator authzRequestDTOGeneratorInstance = new AuthzRequestDTOGenerator();

    public static AuthzRequestDTOGenerator getInstance() {

        if (authzRequestDTOGeneratorInstance == null) {

            synchronized (AuthzRequestDTOGenerator.class) {

                if (authzRequestDTOGeneratorInstance == null) {

                    /* instance will be created at request time */
                    authzRequestDTOGeneratorInstance = new AuthzRequestDTOGenerator();
                }
            }
        }
        return authzRequestDTOGeneratorInstance;

    }

    public AuthzRequestDTO buildAuthzRequestDO(CibaAuthResponseDTO cibaAuthResponseDTO, CibaAuthCodeDO cibaAuthCodeDO)
            throws CibaCoreException {

        try {
            AuthzRequestDTO authzRequestDTO = new AuthzRequestDTO();

            String clientID = cibaAuthResponseDTO.getAudience();
            String user = cibaAuthResponseDTO.getUserHint();

            OAuthAppDO appDO = null;

            appDO = OAuth2Util.getAppInformationByClientId(clientID);

            //log.info(appDO.getCallbackUrl());

            String callbackUri = appDO.getCallbackUrl();

            authzRequestDTO.setAuthReqIDasState(cibaAuthCodeDO.getCibaAuthCodeDOKey());
            authzRequestDTO.setCallBackUrl(callbackUri);
            authzRequestDTO.setUser(user);
            authzRequestDTO.setClient_id(clientID);
            authzRequestDTO.setBindingMessage(cibaAuthCodeDO.getBindingMessage());
            authzRequestDTO.setTransactionDetails(cibaAuthCodeDO.getTransactionContext());
            authzRequestDTO.setScope(cibaAuthCodeDO.getScope());

            return authzRequestDTO;

        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

}
