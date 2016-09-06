/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.data.publisher.oauth.model;

import org.wso2.carbon.identity.base.IdentityRuntimeException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class TokenData<T1 extends Object, T2 extends Object> {

    private String user;
    private String tenantDomain;
    private String userStoreDomain;
    private String clientId;
    private String grantType;
    private String tokenId;
    private String authzScopes;
    private String unAuthzScopes;
    private boolean isSuccess;
    private String errorCode;
    private String errorMsg;
    private long accessTokenValidityMillis;
    private long refreshTokenValidityMillis;
    private long issuedTime;
    private boolean isActive;
    protected Map<T1, T2> parameters = new HashMap<>();

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    public String getUserStoreDomain() {
        return userStoreDomain;
    }

    public void setUserStoreDomain(String userStoreDomain) {
        this.userStoreDomain = userStoreDomain;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getTokenId() {
        return tokenId;
    }

    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    public String getAuthzScopes() {
        return authzScopes;
    }

    public void setAuthzScopes(String authzScopes) {
        this.authzScopes = authzScopes;
    }

    public String getUnAuthzScopes() {
        return unAuthzScopes;
    }

    public void setUnAuthzScopes(String unAuthzScopes) {
        this.unAuthzScopes = unAuthzScopes;
    }

    public boolean isSuccess() {
        return isSuccess;
    }

    public void setIsSuccess(boolean isSuccess) {
        this.isSuccess = isSuccess;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public String getErrorMsg() {
        return errorMsg;
    }

    public void setErrorMsg(String errorMsg) {
        this.errorMsg = errorMsg;
    }

    public long getAccessTokenValidityMillis() {
        return accessTokenValidityMillis;
    }

    public void setAccessTokenValidityMillis(long accessTokenValidityMillis) {
        this.accessTokenValidityMillis = accessTokenValidityMillis;
    }

    public long getRefreshTokenValidityMillis() {
        return refreshTokenValidityMillis;
    }

    public void setRefreshTokenValidityMillis(long refreshTokenValidityMillis) {
        this.refreshTokenValidityMillis = refreshTokenValidityMillis;
    }

    public long getIssuedTime() {
        return issuedTime;
    }

    public void setIssuedTime(long issuedTime) {
        this.issuedTime = issuedTime;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setIsActive(boolean isActive) {
        this.isActive = isActive;
    }

    public void addParameter(T1 key, T2 value) {
        if (this.parameters.containsKey(key)) {
            throw IdentityRuntimeException.error("Parameters map trying to override existing key " +
                    key);
        }
        parameters.put(key, value);
    }

    public void addParameters(Map<T1, T2> parameters) {
        for (Map.Entry<T1, T2> parameter : parameters.entrySet()) {
            if (this.parameters.containsKey(parameter.getKey())) {
                throw IdentityRuntimeException.error("Parameters map trying to override existing key " + parameter.getKey());
            }
            parameters.put(parameter.getKey(), parameter.getValue());
        }
    }

    public Map<T1, T2> getParameters() {
        return Collections.unmodifiableMap(parameters);
    }

    public T2 getParameter(T1 key) {
        return parameters.get(key);
    }
}
