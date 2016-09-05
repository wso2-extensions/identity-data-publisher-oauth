package org.wso2.carbon.identity.data.publisher.oauth.model;

public class TokenData {

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
}
