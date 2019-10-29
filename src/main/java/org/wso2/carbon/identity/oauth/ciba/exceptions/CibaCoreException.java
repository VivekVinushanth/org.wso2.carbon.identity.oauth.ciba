package org.wso2.carbon.identity.oauth.ciba.exceptions;

public class CibaCoreException extends Exception {

    private int Status;
    private String ErrorCode;
    private String ErrorDescritption;

    public CibaCoreException(int status, String errorCode, String errorDescritption) {

        this.Status = status;
        this.ErrorCode = errorCode;
        this.ErrorDescritption = errorDescritption;

    }

    public int getStatus() {

        return Status;
    }

    public void setStatus(int status) {

        Status = status;
    }

    public String getErrorCode() {

        return ErrorCode;
    }

    public void setErrorCode(String errorCode) {

        ErrorCode = errorCode;
    }

    public String getErrorDescritption() {

        return ErrorDescritption;
    }

    public void setErrorDescritption(String errorDescritption) {

        ErrorDescritption = errorDescritption;
    }
}
