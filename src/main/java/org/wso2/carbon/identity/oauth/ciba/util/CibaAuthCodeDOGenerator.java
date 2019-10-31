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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.wso2.carbon.identity.oauth.ciba.common.AuthenticationStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;

import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import javax.servlet.http.HttpServletResponse;

/**
 * This class is responsible for generating AuthCodeDO.
 */
public class CibaAuthCodeDOGenerator {

    private static final Log log = LogFactory.getLog(CibaAuthCodeDOGenerator.class);

    private CibaAuthCodeDOGenerator() {

    }

    private static CibaAuthCodeDOGenerator cibaAuthCodeDOGeneratorInstance = new CibaAuthCodeDOGenerator();

    public static CibaAuthCodeDOGenerator getInstance() {

        if (cibaAuthCodeDOGeneratorInstance == null) {

            synchronized (CibaAuthCodeDOGenerator.class) {

                if (cibaAuthCodeDOGeneratorInstance == null) {

                    /* instance will be created at request time */
                    cibaAuthCodeDOGeneratorInstance = new CibaAuthCodeDOGenerator();
                }
            }
        }
        return cibaAuthCodeDOGeneratorInstance;

    }


    /**
     * This method builds and returns AuthorizationRequestDTO.
     *
     * @param cibaAuthCode      JWT with claims necessary for AuthCodeDO .
     * @param cibaAuthResponseDTO Status of the relevant Ciba Authentication.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public CibaAuthCodeDO generateCibaAuthCodeDO(String cibaAuthCode, CibaAuthResponseDTO cibaAuthResponseDTO)
            throws CibaCoreException {

        try {
            SignedJWT signedJWT = SignedJWT.parse(cibaAuthCode);
            JSONObject jo = signedJWT.getJWTClaimsSet().toJSONObject();



            long lastPolledTime = cibaAuthResponseDTO.getIssuedTime();
            long expiryTime = cibaAuthResponseDTO.getExpiredTime();

            String hashValueOfCibaAuthReqId = AuthReqManager.getInstance().createHash(cibaAuthCode);

            String bindingMessage = cibaAuthResponseDTO.getBindingMessage();
            String transactionContext = cibaAuthResponseDTO.getTransactionContext();
            String scope = cibaAuthResponseDTO.getScope();


            CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();
            cibaAuthCodeDO.setCibaAuthCodeDOKey(AuthReqManager.getInstance().getUniqueAuthCodeDOKey());
            cibaAuthCodeDO.setHashedCibaAuthReqId(hashValueOfCibaAuthReqId);
            cibaAuthCodeDO.setAuthenticationStatus(AuthenticationStatus.REQUESTED.toString());
            cibaAuthCodeDO.setLastPolledTime(lastPolledTime);
            cibaAuthCodeDO.setInterval(CibaParams.interval);
            cibaAuthCodeDO.setExpiryTime(expiryTime);
            cibaAuthCodeDO.setBindingMessage(bindingMessage);
            cibaAuthCodeDO.setTransactionContext(transactionContext);
            cibaAuthCodeDO.setScope(scope);

            if (log.isDebugEnabled()) {
                log.debug("Successful in creating AuthCodeDO with cibaAuthCode = " +  cibaAuthCode);
            }

            return cibaAuthCodeDO;
        } catch (ParseException | NoSuchAlgorithmException e) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to create AuthCodeDO with cibaAuthCode = " +  cibaAuthCode);
            }

            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }
}
