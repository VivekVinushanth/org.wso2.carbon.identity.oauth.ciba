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

package org.wso2.carbon.identity.oauth.ciba.model;

import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;

public class CibaAuthResponse extends OAuthResponse{

        protected CibaAuthResponse(String uri, int responseStatus) {
            super(uri, responseStatus);
        }




    public static CibaAuthResponse.CibaAuthResponseBuilder cibaAuthenticationResponse( int code) {
        return new CibaAuthResponse.CibaAuthResponseBuilder(code);
    }

        public static class CibaAuthResponseBuilder extends OAuthResponseBuilder {
            public CibaAuthResponseBuilder(int responseCode) {
                super(responseCode);
            }

            public CibaAuthResponseBuilder setAuthReqID(String authReqID) {
                this.parameters.put(CibaParams.AUTH_REQ_ID, authReqID);
                return this;
            }

            public CibaAuthResponseBuilder setExpiresIn(String expiresIn) {
                this.parameters.put(CibaParams.EXPIRES_IN, expiresIn == null ? null : Long.valueOf(expiresIn));
                return this;
            }
            public CibaAuthResponseBuilder setInterval(String interval) {
                this.parameters.put(CibaParams.INTERVAL, interval == null ? null : Long.valueOf(interval));
                return this;
            }


            public CibaAuthResponse.CibaAuthResponseBuilder setState(String state) {
                this.parameters.put("state", state);
                return this;
            }


        }
    }


