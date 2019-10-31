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

package org.wso2.carbon.identity.oauth.ciba.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletResponse;

/**
 * This class is responsible for generating Authorization Request DTO.
 */
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

    /**
     * This method builds and returns AuthorizationRequestDTO.
     *
     * @param cibaAuthCodeDO      DO with information regarding authenticationRequest.
     * @param cibaAuthResponseDTO Status of the relevant Ciba Authentication.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public AuthzRequestDTO buildAuthzRequestDO(CibaAuthResponseDTO cibaAuthResponseDTO, CibaAuthCodeDO cibaAuthCodeDO)
            throws CibaCoreException {

        String clientID = cibaAuthResponseDTO.getAudience();
        try {
            AuthzRequestDTO authzRequestDTO = new AuthzRequestDTO();

            String user = cibaAuthResponseDTO.getUserHint();

            OAuthAppDO appDO = OAuth2Util.getAppInformationByClientId(clientID);

            String callbackUri = appDO.getCallbackUrl();

            authzRequestDTO.setAuthReqIDasState(cibaAuthCodeDO.getCibaAuthCodeDOKey());
            authzRequestDTO.setCallBackUrl(callbackUri);
            authzRequestDTO.setUser(user);
            authzRequestDTO.setClient_id(clientID);
            authzRequestDTO.setBindingMessage(cibaAuthCodeDO.getBindingMessage());
            authzRequestDTO.setTransactionDetails(cibaAuthCodeDO.getTransactionContext());
            authzRequestDTO.setScope(cibaAuthCodeDO.getScope());

            if (log.isDebugEnabled()) {
                log.debug("Successful in creating AuthorizeRequestDTO for the client : " + clientID);
            }
            return authzRequestDTO;

        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {

            if (log.isDebugEnabled()) {
                log.debug("Error in creating AuthorizeRequestDTO for the client : " + clientID);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

}
