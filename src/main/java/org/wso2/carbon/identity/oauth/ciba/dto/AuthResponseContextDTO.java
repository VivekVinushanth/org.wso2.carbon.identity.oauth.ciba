package org.wso2.carbon.identity.oauth.ciba.dto;

public class AuthResponseContextDTO {

    private static int ERROR_CODE;
    private static String ERROR;
    private  static String ERROR_DESCRIPTION;

    public AuthResponseContextDTO(){}

    public  int getErrorCode() {
        return ERROR_CODE;
    }

    public  void setErrorCode(int errorCode) {
        ERROR_CODE = errorCode;
    }

    public  String getError() {
        return ERROR;
    }

    public  void setError(String error) {
        ERROR = error;
    }

    public  String getErrorDescription() {
        return ERROR_DESCRIPTION;
    }

    public  void setErrorDescription(String errorDescription) {
        ERROR_DESCRIPTION = errorDescription;
    }




}
