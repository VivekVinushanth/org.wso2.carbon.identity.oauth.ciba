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
