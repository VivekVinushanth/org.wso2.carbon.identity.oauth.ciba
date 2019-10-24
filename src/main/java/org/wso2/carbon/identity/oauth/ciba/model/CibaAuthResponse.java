package org.wso2.carbon.identity.oauth.ciba.model;

import org.apache.oltu.oauth2.common.message.OAuthResponse;
import javax.servlet.http.HttpServletRequest;

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
                this.parameters.put("auth_req_id", authReqID);
                return this;
            }

            public CibaAuthResponseBuilder setExpiresIn(String expiresIn) {
                this.parameters.put("expires_in", expiresIn == null ? null : Long.valueOf(expiresIn));
                return this;
            }
            public CibaAuthResponseBuilder setInterval(String interval) {
                this.parameters.put("interval", interval == null ? null : Long.valueOf(interval));
                return this;
            }


            public CibaAuthResponse.CibaAuthResponseBuilder setState(String state) {
                this.parameters.put("state", state);
                return this;
            }


        }
    }


