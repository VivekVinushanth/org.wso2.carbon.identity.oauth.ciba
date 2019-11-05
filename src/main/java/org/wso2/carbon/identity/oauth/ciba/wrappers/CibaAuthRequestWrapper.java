/*
package org.wso2.carbon.identity.oauth.ciba.wrappers;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletRequest;
import javax.servlet.ServletRequestWrapper;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class CibaAuthRequestWrapper extends ServletRequestWrapper {

    private Map extraParameters;
    private Map parametersMap;
    private Map transitionMap;

    public CibaAuthRequestWrapper(HttpServletRequest request) {

        super(request);
        extraParameters = new HashMap();
        parametersMap = this.getRequest().getParameterMap().remove();
    }

    public String getParameter(String name) {

        if (extraParameters.containsKey(name)) {
            return (String) extraParameters.get(name);
        } else {
            return super.getParameter(name);
        }
    }

    public void setParameter(String name, String value) {

        extraParameters.put(name, value);
    }


    public void removeParameter(String name) {

        parametersMap.remove(name);

        for (parametersMap.ge:
             ) {

        }

    }

}

*/
