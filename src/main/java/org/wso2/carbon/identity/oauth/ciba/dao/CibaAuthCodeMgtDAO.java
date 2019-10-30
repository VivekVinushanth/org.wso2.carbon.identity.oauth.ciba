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

package org.wso2.carbon.identity.oauth.ciba.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.servlet.http.HttpServletResponse;

/**
 * This class manages the CibaAuthCode and its storage.
 */
public class CibaAuthCodeMgtDAO {

    private static final Log log = LogFactory.getLog(CibaAuthCodeMgtDAO.class);

    private CibaAuthCodeMgtDAO() {

    }

    private static CibaAuthCodeMgtDAO cibaAuthCodeMgtDAOInstance = new CibaAuthCodeMgtDAO();

    public static CibaAuthCodeMgtDAO getInstance() {

        if (cibaAuthCodeMgtDAOInstance == null) {

            synchronized (CibaAuthCodeMgtDAO.class) {

                if (cibaAuthCodeMgtDAOInstance == null) {

                    /* instance will be created at request time */
                    cibaAuthCodeMgtDAOInstance = new CibaAuthCodeMgtDAO();
                }
            }
        }
        return cibaAuthCodeMgtDAOInstance;

    }

    /**
     * This method persist the CibaAuthCodeDO.
     *
     * @param cibaAuthCodeDO Data object that accumulates  CibaAuthCode.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void persistCibaAuthCode(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.STORE_CIBA_AUTH_REQ_CODE)) {
                prepStmt.setString(1, cibaAuthCodeDO.getCibaAuthCodeDOKey());
                prepStmt.setString(2, cibaAuthCodeDO.getHashedCibaAuthReqId());
                prepStmt.setString(3, cibaAuthCodeDO.getAuthenticationStatus());
                prepStmt.setLong(4, cibaAuthCodeDO.getLastPolledTime());
                prepStmt.setLong(5, cibaAuthCodeDO.getInterval());
                prepStmt.setLong(6, cibaAuthCodeDO.getExpiryTime());
                prepStmt.setString(7, cibaAuthCodeDO.getBindingMessage());
                prepStmt.setString(8, cibaAuthCodeDO.getTransactionContext());
                prepStmt.setString(9, cibaAuthCodeDO.getScope());
                prepStmt.execute();
                connection.commit();

                if (log.isDebugEnabled()) {
                    log.debug(
                            "Successfully persisted cibaAuthCodeDO for unique cibaAuthCodeDOKey : " +
                                    cibaAuthCodeDO.getCibaAuthCodeDOKey());
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Error occured while persisting cibaAuthCodeDO for unique cibaAuthCodeDOKey : " +
                                cibaAuthCodeDO.getCibaAuthCodeDOKey());
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * This method returns CibaAuthCodeDO identified by unique cibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey Identifier of CibaAuthCode.
     * @param cibaAuthCodeDO    Captures fields related to authentication and token requests.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void getCibaAuthCodeDO(String cibaAuthCodeDOKey, CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_AUTH_CODE_DO_FROM_CIBA_AUTH_CODE_DO_KEY)) {

                prepStmt.setString(1, cibaAuthCodeDOKey);

                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {
                    cibaAuthCodeDO.setCibaAuthCodeDOKey(resultSet.getString(1));
                    cibaAuthCodeDO.setHashedCibaAuthReqId(resultSet.getString(2));
                    cibaAuthCodeDO.setAuthenticationStatus(resultSet.getString(3));
                    cibaAuthCodeDO.setLastPolledTime(resultSet.getLong(4));
                    cibaAuthCodeDO.setInterval(resultSet.getLong(5));
                    cibaAuthCodeDO.setAuthenticatedUser(resultSet.getString(6));
                    cibaAuthCodeDO.setExpiryTime(resultSet.getLong(7));

                }

                if (log.isDebugEnabled()) {
                    log.debug(
                            "Successfully obtained cibaAuthCodeDO for unique cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
                }
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Error in obtaining cibaAuthCodeDO for unique cibaAuthCodeDOKey : " + cibaAuthCodeDOKey);
            }
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }

}
