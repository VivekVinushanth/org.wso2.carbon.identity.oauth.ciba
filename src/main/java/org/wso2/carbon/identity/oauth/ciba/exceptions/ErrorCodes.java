package org.wso2.carbon.identity.oauth.ciba.exceptions;

public class ErrorCodes {

    public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
    public static final String SERVER_ERROR = "server_error";
    public static final String ACCESS_DENIED = "access_denied";
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String BAD_REQUEST = "bad_request";


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

    }
}
