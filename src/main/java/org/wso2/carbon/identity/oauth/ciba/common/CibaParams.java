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

package org.wso2.carbon.identity.oauth.ciba.common;

/**
 * This class is meant to store the features of the transaction.
 * */
public class CibaParams {



    public static long INTERVAL_INCREMENT =3 ;
    public static long expiresIn = 3600;
    public static long interval = 2;
    public static long MAXIMUM_REQUESTED_EXPIRY = 3600;


    public static final String EXPIRES_IN = "expiresIn";
    public static final  String INTERVAL = "interval";
    public static final String AUTH_REQ_ID = "auth_req_id";
    public static final String REQUEST = "request";


    //params for authorize request and to validate token request.
    public static final String OAUTH_CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba";
    public static final String AUTHORIZE_ENDPOINT = "https://localhost:9443/oauth2/authorize";
    public static final String AUTHORIZE_ENDPOINT_PATH = "/oauth2/authorize";
    public static final String RESPONSE_TYPE_VALUE = "ciba";
    public static final String CLIENT_ID = "client_id";
    public static final String STATE_PARAMATER = "state";
    public static final String USER_IDENTITY = "user";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String RESPONSE_TYPE = "response_type";
    public static final String NONCE = "nonce";

    public static final String  CIBA_AS_AUDIENCE = "https://localhost:9443/oauth2/ciba";


    //Parameters for authorize request.
    public static final String SCOPE = "scope" ;
    public static final String BINDING_MESSAGE = "binding_message";
    public static final String TRANSACTION_CONTEXT = "transaction_context";
    public static final int PORT = 9443 ;
    public static final String SCHEME = "https";
    public static final String HOST = "localhost" ;

    private CibaParams() {

    }
}
