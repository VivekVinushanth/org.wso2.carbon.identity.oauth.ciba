  /*
   * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

  package org.wso2.carbon.identity.oauth.ciba.grant;

import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.mockito.Mock;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationCodeGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.*;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;


import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.time.ZonedDateTime;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

    /**
     * This class defines unit test for AuthorizationCodeGrantHandler class
     */
    @WithCarbonHome
    public class CibaGrantHandlerTest extends PowerMockTestCase {

        public static final String CLIENT_ID_VALUE = "clientIdValue";
        public static final String INVALID_CLIENT = "invalidClient";
        public static final String  CIBA_AS_AUDIENCE = "https://localhost:9443/oauth2/ciba";
        private static final long CURRENT_TIME = ZonedDateTime.now().toInstant().toEpochMilli();;
        OAuthServerConfiguration oAuthServerConfiguration;
        AuthorizationCodeGrantHandler authorizationCodeGrantHandler;

        @BeforeTest()
        public void setUp() {
        }

        @DataProvider(name = "providePollingParams")
        public Object[][] providePollingParams() {
            initMocks(this);

            return new Object[][] {
                    {0,0,false},
                    {0,0,false},
                    {-1,0,false},
                    {0,-1,false},
                    {CURRENT_TIME-1000,2000,false},
                    {CURRENT_TIME-1,2000,false}

            };
        }

        @Test(dataProvider = "providePollingParams")
        public void testIsCorrectPollingFrequency(long lastPolledTime, long interval, boolean expected)
                throws NoSuchAlgorithmException, SQLException, ClassNotFoundException {
            CibaAuthCodeDO cibaAuthCodeDO = new CibaAuthCodeDO();

            cibaAuthCodeDO.setLastPolledTime(lastPolledTime);
            cibaAuthCodeDO.setInterval(interval);
            CibaGrantHandler cibaGrantHandler = mock(CibaGrantHandler.class);

            boolean result = cibaGrantHandler.IsCorrectPollingFrequency(cibaAuthCodeDO);
            assertEquals(result,expected);
        }

        @DataProvider(name = "provideIssuerParams")
        public Object[][] provideIssuerParams() {
            initMocks(this);

            return new Object[][] {
                    {"",false},
                    {"random string",false},
                    {"null",false},
                    {null,false},
                   // {CIBA_AS_AUDIENCE,true}

            };
        }

        @Test(dataProvider = "provideIssuerParams")
        public void testIsValidIssuer(String issuer, boolean expected) {
            JSONObject jo = new JSONObject();
            jo.put("iss",issuer);
            CibaGrantHandler cibaGrantHandler = mock(CibaGrantHandler.class);

            boolean result = cibaGrantHandler.isValidIssuer(jo);
            assertEquals(result,expected);
        }


}
