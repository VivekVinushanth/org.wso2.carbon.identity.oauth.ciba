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
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;


/**
 * This class maanges the CibaAuthCode and its storage.
 * */
public class CibAuthCodeMgtDAO {


    private static final Log log = LogFactory.getLog(CibAuthCodeMgtDAO.class);
    private CibAuthCodeMgtDAO() {

    }

    private static CibAuthCodeMgtDAO cibAuthCodeMgtDAOInstance = new CibAuthCodeMgtDAO();

    public static CibAuthCodeMgtDAO getInstance() {
        if (cibAuthCodeMgtDAOInstance == null) {

            synchronized (CibAuthCodeMgtDAO.class) {

                if (cibAuthCodeMgtDAOInstance == null) {

                    /* instance will be created at request time */
                    cibAuthCodeMgtDAOInstance = new CibAuthCodeMgtDAO();
                }
            }
        }
        return cibAuthCodeMgtDAOInstance;


    }


    /**
     * This method persist the CibaAuthCode.
     * @param cibaAuthCodeDO Data object that accumilates  CibaAuthCode.
     * @throws SQLException
     */
    public void persistCibaAuthReqCode (CibaAuthCodeDO cibaAuthCodeDO) throws SQLException, ClassNotFoundException {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.
                    CibaSQLQueries.STORE_CIBA_AUTH_REQ_CODE);
            prepStmt.setString(1, cibaAuthCodeDO.getCibaAuthCodeID());
            prepStmt.setString(2, cibaAuthCodeDO.getCibaAuthCode());
            prepStmt.setString(3, cibaAuthCodeDO.getHashedCibaAuthCode());
            prepStmt.setString(4, cibaAuthCodeDO.getAuthenticationStatus());
            prepStmt.setLong(5, cibaAuthCodeDO.getLastPolledTime());
            prepStmt.setLong(6, cibaAuthCodeDO.getInterval());
            prepStmt.setLong(7,cibaAuthCodeDO.getExpiryTime());
            prepStmt.setString(8,cibaAuthCodeDO.getBindingMessage());
            prepStmt.setString(9,cibaAuthCodeDO.getTransactionContext());
            prepStmt.setString(10,cibaAuthCodeDO.getScope());
            prepStmt.execute();
            connection.commit();
        }
    }

}
