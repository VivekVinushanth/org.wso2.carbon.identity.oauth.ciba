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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.exceptions;

public class ErrorCodes {

    public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
    public static final String SERVER_ERROR = "server_error";
    public static final String ACCESS_DENIED = "access_denied";
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String BAD_REQUEST = "bad_request";
    public static final String UNAUTHORIZED_USER = "unauthorized_user";


    private ErrorCodes(){}

    public class SubErrorCodes {

        public static final String IMPROPER_SINGED_JWT = "Improper signed JWT";
        public static final String INVALID_AUTHORIZATION_REQUEST = "invalid_authorization_request";
        public static final String INVALID_REQUEST_OBJECT = "invalid_request_object";
        public static final String UNEXPECTED_SERVER_ERROR = "unexpected_server_error";
        public static final String INVALID_REQUEST = "invalid_request";
        public static final String CONSENT_DENIED = "consent_denied";
        public static final String ACCESS_DENIED = "access_denied";
        public static final String INVALID_PARAMETERS = "invalid_parameters";
        public static final String UNEXPECTED_PARSER_ERROR = "unexpected_parser_error";
        public static final String UNREGISTERED_USER = "user_unknown";
    }
}
