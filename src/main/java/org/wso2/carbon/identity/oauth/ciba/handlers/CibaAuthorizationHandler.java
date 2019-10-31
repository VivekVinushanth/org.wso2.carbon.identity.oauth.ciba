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


package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import javax.servlet.http.HttpServletResponse;

/**
 * This class handle mechanism of making authorize request to the authorize request.
 */
public class CibaAuthorizationHandler {

    private static final Log log = LogFactory.getLog(CibaAuthorizationHandler.class);

    private CibaAuthorizationHandler() {

    }

    private static CibaAuthorizationHandler cibaAuthorizationHandlerInstance = new CibaAuthorizationHandler();

    public static CibaAuthorizationHandler getInstance() {

        if (cibaAuthorizationHandlerInstance == null) {

            synchronized (CibaAuthorizationHandler.class) {

                if (cibaAuthorizationHandlerInstance == null) {

                    /* instance will be created at request time */
                    cibaAuthorizationHandlerInstance = new CibaAuthorizationHandler();
                }
            }
        }
        return cibaAuthorizationHandlerInstance;
    }

    /**
     * Trigger authorize request after building the url.
     *
     * @param authzRequestDto AuthorizeRequest Data Transfer Object..
     * @throws CibaCoreException
     */
    public void initiateAuthzRequest(AuthzRequestDTO authzRequestDto) throws CibaCoreException {

        // Build the URI as a string.
        String uriString = null;
        try {
            uriString = new URIBuilder()
                    .setScheme(CibaParams.SCHEME)
                    .setHost(CibaParams.HOST)
                    .setPort(CibaParams.PORT)
                    .setPath(CibaParams.AUTHORIZE_ENDPOINT_PATH)
                    .setParameter(CibaParams.SCOPE, authzRequestDto.getScope())
                    .setParameter(CibaParams.RESPONSE_TYPE, CibaParams.RESPONSE_TYPE_VALUE)
                    .setParameter(CibaParams.NONCE, authzRequestDto.getAuthReqIDasState())
                    .setParameter(CibaParams.REDIRECT_URI, authzRequestDto.getCallBackUrl())
                    .setParameter(CibaParams.CLIENT_ID, authzRequestDto.getClient_id())
                    .setParameter(CibaParams.USER_IDENTITY, authzRequestDto.getUser())
                    .setParameter(CibaParams.BINDING_MESSAGE, authzRequestDto.getBindingMessage())
                    .setParameter(CibaParams.TRANSACTION_CONTEXT, authzRequestDto.getTransactionContext())
                    .build().toString();

            if (log.isDebugEnabled()) {
                log.debug("Building AuthorizeRequest URL from CIBA component for the user : " +
                        authzRequestDto.getUser() + " to continue the authentication request made by client with " +
                        "clientID : " + authzRequestDto.getClient_id());
            }

            // Fire authorize request and forget.
            this.fireAndForget(uriString);

        } catch (CibaCoreException | URISyntaxException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ErrorCodes.INTERNAL_SERVER_ERROR
                    , e.getMessage());

        }
    }

    /**
     * Initiate the async authorize request.
     *
     * @param url URL for authorize request.
     * @throws CibaCoreException Exception from CibaCore component.
     */
    public void fireAndForget(String url) throws CibaCoreException {
        //Do a fire and forget kind of HTTP call to authorize endpoint.
        try {
            CloseableHttpAsyncClient client = HttpAsyncClients.createDefault();
            client.start();
            HttpGet request = new HttpGet(url);

            if (log.isDebugEnabled()) {
                log.info("CIBA AuthorizationHandler initiating the authorize request to the authorize endpoint." +
                        "The request URL is : " + url);
            }

            Future<HttpResponse> future = client.execute(request, null);
            HttpResponse response = future.get();

            if (log.isDebugEnabled()) {
                log.warn("Closing the authorize request after firing the authorize request with URL : " + url);
            }

            // Close the client at any response status.
            client.close();

        } catch (InterruptedException | ExecutionException | IOException ex) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ErrorCodes.INTERNAL_SERVER_ERROR
                    , ex.getMessage());

        }

    }

}
