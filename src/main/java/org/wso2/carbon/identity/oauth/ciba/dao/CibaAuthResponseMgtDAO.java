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
 * This class is responsible for Ciba Authentication response and persisting of CibaAuthCode.
 */
public class CibaAuthResponseMgtDAO {

    private static final Log log = LogFactory.getLog(CibaAuthResponseMgtDAO.class);

    private CibaAuthResponseMgtDAO() {

    }

    private static CibaAuthResponseMgtDAO cibaAuthResponseMgtDAOInstance = new CibaAuthResponseMgtDAO();

    public static CibaAuthResponseMgtDAO getInstance() {

        if (cibaAuthResponseMgtDAOInstance == null) {

            synchronized (CibaAuthResponseMgtDAO.class) {

                if (cibaAuthResponseMgtDAOInstance == null) {

                    /* instance will be created at request time */
                    cibaAuthResponseMgtDAOInstance = new CibaAuthResponseMgtDAO();
                }
            }
        }
        return cibaAuthResponseMgtDAOInstance;

    }

    /**
     * This method store the status of the releavant CibAuthCode identified by the CibaAuthcodeID.
     *
     * @param cibaAuthReqIdKey        Identifier for CibaAuthReqId.
     * @param cibaAuthentcationStatus Status of the relevant Ciba Authentication.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void persistStatus(String cibaAuthReqIdKey, String cibaAuthentcationStatus) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.UPDATE_AUTHENTICATION_STATUS)) {

                prepStmt.setString(1, cibaAuthentcationStatus);
                prepStmt.setString(2, cibaAuthReqIdKey);

                prepStmt.execute();
                connection.commit();
            }
        } catch (SQLException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, "SQL exception in persisting authenticated_status in to " +
                    "database for CIBA." + e.getMessage());
        }
    }

    /**
     * This method store the authenticated user of the releavant CibAuthCode identified by the CibaAuthcodeID.
     *
     * @param cibaAuthReqIdKey      Identifier for CibaAuthCode
     * @param cibaAuthenticatedUser authenticated user for the relevant CibaAuthCode
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void persistUser(String cibaAuthReqIdKey, String cibaAuthenticatedUser) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    UPDATE_CIBA_AUTHENTICATED_USER)) {
                prepStmt.setString(1, cibaAuthenticatedUser);
                prepStmt.setString(2, cibaAuthReqIdKey);

                prepStmt.execute();
                connection.commit();
            }
        } catch (SQLException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, "SQL exception in persisting authenticated_user in to " +
                    "database for CIBA." + e.getMessage());
        }
    }

    /**
     * This method check whether hash of CibaAuthCode exists.
     *
     * @param hashedCibaAuthReqId hash of CibaAuthReqID.
     * @return boolean Returns whether given HashedAuthReqId present or not.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public boolean isHashedAuthIDExists(String hashedCibaAuthReqId) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {

            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    CHECK_IF_AUTH_REQ_ID_HASH_EXISTS)) {
                prepStmt.setString(1, hashedCibaAuthReqId);

                ResultSet resultSet = prepStmt.executeQuery();

                int count;

                while (resultSet.next()) {
                    count = (resultSet.getInt(1));

                    if (count >= 1) {
                        //do nothing
                        prepStmt.close();
                        return true;

                    } else {
                        //connection.close();
                        prepStmt.close();
                        return false;
                    }
                }

                return false;
            }
        } catch (SQLException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * This method returns CibaAuthCodeID for the hash of CibaAuthcode.
     *
     * @param hashedCibaAuthReqId hash of CibaAuthReqId.
     * @return String Returns key of CibaAuthReqId.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public String getCibaAuthReqIdKey(String hashedCibaAuthReqId) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    RETRIEVE_CIBA_AUTH_REQ_ID_KEY_BY_CIBA_AUTH_REQ_ID_HASH)) {
                prepStmt.setString(1, hashedCibaAuthReqId);

                ResultSet resultSet = prepStmt.executeQuery();

                if (resultSet.next()) {
                    return resultSet.getString(1);
                } else {
                    return null;
                }
            }
        } catch (SQLException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }

    /**
     * This method returns the lastpolledtime of cibaAuthReqId with relevant key.
     *
     * @param cibaAuthReqIdKey identifier of CibaAuthReqId.
     * @return long Returns lastPolledTime.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public long getCibaLastPolledTime(String cibaAuthReqIdKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_LAST_POLLED_TIME)) {
                prepStmt.setString(1, cibaAuthReqIdKey);

                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {
                    return resultSet.getLong(1);
                } else {
                    return 0;
                }
            }

        } catch (SQLException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * This method returns the polling Interval of cibaAuthReqId with relevant key.
     *
     * @param cibaAuthReqIdKey identifier of CibaAuthReqId.
     * @return long Returns pollingInterval of tokenRequest.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public long getCibaPollingInterval(String cibaAuthReqIdKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_POLLING_INTERVAL)) {
                prepStmt.setString(1, cibaAuthReqIdKey);

                ResultSet rs = prepStmt.executeQuery();
                if (rs.next()) {
                    return rs.getLong(1);
                } else {
                    return 0;
                }
            }
        } catch (SQLException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }

    /**
     * This method updates the last polled time of cibaAuthReqId with relevant key.
     *
     * @param cibaAuthReqIdKey identifier of CibaAuthCode
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void updateLastPollingTime(String cibaAuthReqIdKey, long currentTime)
            throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_LAST_POLLED_TIME)) {
                prepStmt.setLong(1, currentTime);
                prepStmt.setString(2, cibaAuthReqIdKey);

                prepStmt.execute();
                connection.commit();
            }
        } catch (SQLException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * This method updates the polling Interval of cibaAuthReqId with relevant key.
     *
     * @param cibaAuthReqIdKey identifier of CibaAuthCode
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void updatePollingInterval(String cibaAuthReqIdKey, long newInterval)
            throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.UPDATE_POLLING_INTERVAL)) {
                prepStmt.setLong(1, newInterval);
                prepStmt.setString(2, cibaAuthReqIdKey);

                prepStmt.execute();
                connection.commit();
            }
        } catch (SQLException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * This method updates the polling Interval of cibaAuthReqId with relevant key.
     *
     * @param cibaAuthReqIdKey identifier of CibaAuthCode
     * @return String Returns AuthenticationStatus.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public String getAuthenticationStatus(String cibaAuthReqIdKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.CibaSQLQueries.
                    RETRIEVE_AUTHENTICATION_STATUS)) {
                prepStmt.setString(1, cibaAuthReqIdKey);

                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {
                    return resultSet.getString(1);

                } else {
                    return null;
                }
            }
        } catch (SQLException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * This method returns the authenticated user of cibaAuthReqId with relevant key.
     *
     * @param cibaAuthReqIdKey identifier of CibaAuthCode
     * @return Returns AuthenticatedUser.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public String getAuthenticatedUser(String cibaAuthReqIdKey) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {

            try (PreparedStatement prepStmt =
                         connection.prepareStatement(SQLQueries.CibaSQLQueries.RETRIEVE_AUTHENTICATED_USER)) {
                prepStmt.setString(1, cibaAuthReqIdKey);

                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {
                    return resultSet.getString(1);
                } else {
                    return null;
                }
            }
        } catch (SQLException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * This method updates the polling Interval of cibaAuthReqId with relevant key.
     *
     * @param cibaAuthReqIdKey identifier of CibaAuthCode
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    public void getAuthCodeDO(String cibaAuthReqIdKey, CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.RETRIEVE_AUTH_CODE_DO_FROM_CIBA_CIBA_AUTH_REQ_ID_KEY)) {

                prepStmt.setString(1, cibaAuthReqIdKey);

                ResultSet resultSet = prepStmt.executeQuery();
                if (resultSet.next()) {
                    cibaAuthCodeDO.setCibaAuthReqIdKey(resultSet.getString(1));
                    cibaAuthCodeDO.setHashedCibaAuthReqId(resultSet.getString(2));
                    cibaAuthCodeDO.setAuthenticationStatus(resultSet.getString(3));
                    cibaAuthCodeDO.setLastPolledTime(resultSet.getLong(4));
                    cibaAuthCodeDO.setInterval(resultSet.getLong(5));
                    cibaAuthCodeDO.setAuthenticatedUser(resultSet.getString(6));
                    cibaAuthCodeDO.setExpiryTime(resultSet.getLong(7));

                }
            }
        } catch (SQLException e) {
            throw new CibaCoreException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }
}