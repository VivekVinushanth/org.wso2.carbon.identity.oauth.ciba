package org.wso2.carbon.identity.oauth.ciba.dto;

public class AuthResponseContextDTO {

    private static int STATUS;
    private static String ERROR;
    private  static String ERROR_DESCRIPTION;

    public AuthResponseContextDTO(){}

    public  int getStatus() {
        return STATUS;
    }

    public  void setStatus(int status) {
        STATUS = status;
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
