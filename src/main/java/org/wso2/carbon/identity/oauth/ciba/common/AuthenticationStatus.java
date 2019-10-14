package org.wso2.carbon.identity.oauth.ciba.common;

/**
 * This class is an ENUM which resembles the possible Authentication status.
 * */
public enum AuthenticationStatus {
    REQUESTED,
    FAILED,
    DENIED,
    AUTHENTICATED,
    EXPIRED,
    TOKEN_DELIEVERED
}
