/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.data.publisher.oauth.listener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Map;

/**
 * Audit logger for password grant.
 */
public class PasswordGrantAuditLogger extends AbstractOAuthEventInterceptor {

    private static final Log AUDIT_LOG = LogFactory.getLog("AUDIT_LOG");
    private static final String PASSWORD_GRANT = "password";

    public PasswordGrantAuditLogger() {
        super();
    }

    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO,
                                 OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx,
                                 Map<String, Object> params) throws IdentityOAuth2Exception {

        if (!isPasswordGrant(tokenReqDTO)) {
            return;
        }

        String requestType = "N/A";
        String serviceProvider = "N/A";
        String authenticatedIdp = "N/A";
        String authenticatedSubjectIdentifier = "N/A";
        String authenticatedUserStoreDomain = "N/A";
        String authenticatedUserTenantDomain = "N/A";
        String requestInitiator;
        String auditResult;

        if (tokReqMsgCtx.getProperty("OAuthAppDO") instanceof OAuthAppDO) {
            OAuthAppDO oAuthAppDO = (OAuthAppDO) tokReqMsgCtx.getProperty("OAuthAppDO");
            requestType = getRequestType(tokReqMsgCtx);
            serviceProvider = oAuthAppDO.getApplicationName();
        }

        requestInitiator = getResourceOwnerUsername(tokReqMsgCtx);
        if (isTokenRequestSuccessful(tokReqMsgCtx)) {
            authenticatedSubjectIdentifier = getAuthenticatedSubjectIdentifier(tokReqMsgCtx);
            authenticatedUserStoreDomain = tokReqMsgCtx.getAuthorizedUser().getUserStoreDomain();
            authenticatedUserTenantDomain = tokReqMsgCtx.getAuthorizedUser().getTenantDomain();
            auditResult = FrameworkConstants.AUDIT_SUCCESS;
        } else {
            auditResult = FrameworkConstants.AUDIT_FAILED;
        }

        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + "N/A"
                + "\",\"" + "AuthenticatedUser" + "\" : \"" + authenticatedSubjectIdentifier
                + "\",\"" + "AuthenticatedUserStoreDomain" + "\" : \"" + authenticatedUserStoreDomain
                + "\",\"" + "AuthenticatedUserTenantDomain" + "\" : \"" + authenticatedUserTenantDomain
                + "\",\"" + "ServiceProvider" + "\" : \"" + serviceProvider
                + "\",\"" + "RequestType" + "\" : \"" + requestType
                + "\",\"" + "RelyingParty" + "\" : \"" + tokenReqDTO.getClientId()
                + "\",\"" + "AuthenticatedIdP" + "\" : \"" + authenticatedIdp
                + "\"";

        AUDIT_LOG.info(String.format(FrameworkConstants.AUDIT_MESSAGE,
                requestInitiator,
                "PostTokenIssue",
                "PasswordGrantAuditLogger",
                auditData,
                auditResult)
        );
    }

    /**
     * Returns the 'username' param in the password grant request.
     *
     * @param tokReqMsgCtx
     * @return Full qualified username
     */
    private String getResourceOwnerUsername(OAuthTokenReqMessageContext tokReqMsgCtx) {
        return tokReqMsgCtx.getOauth2AccessTokenReqDTO().getResourceOwnerUsername();
    }

    private String getRequestType(OAuthTokenReqMessageContext tokReqMsgCtx) {
        boolean isOpenIdConnect = OAuth2Util.isOIDCAuthzRequest(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
        return isOpenIdConnect ? FrameworkConstants.OIDC : FrameworkConstants.OAUTH2;
    }

    private String getAuthenticatedSubjectIdentifier(OAuthTokenReqMessageContext tokReqMsgCtx) {
        return tokReqMsgCtx.getAuthorizedUser().getAuthenticatedSubjectIdentifier();
    }

    private boolean isTokenRequestSuccessful(OAuthTokenReqMessageContext tokReqMsgCtx) {
        // If password grant request was successful we will have a valid authorized user set in the token context.
        return tokReqMsgCtx.getAuthorizedUser() != null;
    }

    /**
     * Checks whether request is from password grant.
     *
     * @param tokenReqDTO Token request DTO.
     * @return True if this request is from password grant.
     */
    private boolean isPasswordGrant(OAuth2AccessTokenReqDTO tokenReqDTO) {
        return PASSWORD_GRANT.equals(tokenReqDTO.getGrantType());
    }

    /**
     * Enable audit logger by default
     * @return true if config is not found or if enabled from config.
     */
    public boolean isEnabled() {

        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.
                readEventListenerProperty(AbstractIdentityHandler.class.getName(), this.getClass().getName());
        return identityEventListenerConfig == null || Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }
}
