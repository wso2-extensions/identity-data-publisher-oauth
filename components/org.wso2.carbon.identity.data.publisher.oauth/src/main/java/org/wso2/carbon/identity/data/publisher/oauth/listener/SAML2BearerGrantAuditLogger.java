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

package org.wso2.carbon.identity.data.publisher.oauth.listener;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
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
 * Audit logger for SAMLBearer grant flow.
 */
public class SAML2BearerGrantAuditLogger extends AbstractOAuthEventInterceptor {

    private static final Log AUDIT_LOG = LogFactory.getLog("AUDIT_LOG");
    private static final String SAML20_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:saml2-bearer";
    private static final String OAUTH_APP_DO = "OAuthAppDO";

    /**
     * Obtain the audit logger for SAMLBearer grant flow in both success and fails scenarios.
     */
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO,
                                 OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx,
                                 Map<String, Object> params) throws IdentityOAuth2Exception {

        if (!isSAML2BearerGrant(tokenReqDTO)) {
            return;
        }

        String requestType = "N/A";
        String serviceProvider = "N/A";
        String authenticatedSubjectIdentifier;
        String authenticatedUserStoreDomain;
        String authenticatedUserTenantDomain;
        String requestInitiator;
        String auditResult;

        if (tokReqMsgCtx.getProperty(OAUTH_APP_DO) instanceof OAuthAppDO) {
            OAuthAppDO oAuthAppDO = (OAuthAppDO) tokReqMsgCtx.getProperty(OAUTH_APP_DO);
            requestType = getRequestType(tokReqMsgCtx);
            serviceProvider = oAuthAppDO.getApplicationName();
        }

        requestInitiator = getResourceOwnerUsername(tokReqMsgCtx);
        if (isTokenRequestSuccessful(tokReqMsgCtx)) {
            authenticatedSubjectIdentifier = tokReqMsgCtx.getAuthorizedUser().getLoggableUserId();
            authenticatedUserStoreDomain = tokReqMsgCtx.getAuthorizedUser().getUserStoreDomain();
            authenticatedUserTenantDomain = tokReqMsgCtx.getAuthorizedUser().getTenantDomain();
            auditResult = FrameworkConstants.AUDIT_SUCCESS;

            if (LoggerUtils.isLogMaskingEnable) {
                if (StringUtils.isNotBlank(requestInitiator) && StringUtils.isNotBlank(authenticatedUserTenantDomain)) {
                    requestInitiator = IdentityUtil.getInitiatorId(requestInitiator, authenticatedUserTenantDomain);
                }
                if (StringUtils.isBlank(requestInitiator)) {
                    requestInitiator = LoggerUtils.getMaskedContent(getResourceOwnerUsername(tokReqMsgCtx));
                }
            }

            String auditData = "\"" + "AuthenticatedUser" + "\" : \"" + authenticatedSubjectIdentifier
                    + "\",\"" + "AuthenticatedUserStoreDomain" + "\" : \"" + authenticatedUserStoreDomain
                    + "\",\"" + "AuthenticatedUserTenantDomain" + "\" : \"" + authenticatedUserTenantDomain
                    + "\",\"" + "ServiceProvider" + "\" : \"" + serviceProvider
                    + "\",\"" + "RequestType" + "\" : \"" + requestType
                    + "\",\"" + "RelyingParty" + "\" : \"" + tokenReqDTO.getClientId()
                    + "\"";

            AUDIT_LOG.info(String.format(FrameworkConstants.AUDIT_MESSAGE,
                    requestInitiator,
                    "PostTokenIssue",
                    "SAML2BearerGrantAuditLogger",
                    auditData,
                    auditResult)
            );
        } else {
            if (LoggerUtils.isLogMaskingEnable) {
                requestInitiator = LoggerUtils.getMaskedContent(requestInitiator);
            }
            auditResult = FrameworkConstants.AUDIT_FAILED;
            String error = "Error Description :" + tokenRespDTO.getErrorMsg() + "Error Type :" +
                    tokenRespDTO.getErrorCode();

            AUDIT_LOG.info(String.format(FrameworkConstants.AUDIT_MESSAGE,
                    requestInitiator,
                    "PostTokenIssue",
                    "SAML2BearerGrantAuditLogger",
                    error,
                    auditResult)
            );
        }
    }

    /**
     * Returns the 'username' param in the saml bearer grant request.
     *
     * @param tokReqMsgCtx token request message context
     * @return Full qualified username
     */
    private String getResourceOwnerUsername(OAuthTokenReqMessageContext tokReqMsgCtx) {

        return tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
    }

    private String getRequestType(OAuthTokenReqMessageContext tokReqMsgCtx) {

        boolean isOpenIdConnect = OAuth2Util.isOIDCAuthzRequest(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
        return isOpenIdConnect ? FrameworkConstants.OIDC : FrameworkConstants.OAUTH2;
    }

    private boolean isTokenRequestSuccessful(OAuthTokenReqMessageContext tokReqMsgCtx) {

        return tokReqMsgCtx.getAuthorizedUser() != null;
    }

    /**
     * Checks whether request is from SAMLBearer grant.
     *
     * @param tokenReqDTO Token request DTO.
     * @return True if this request is from SAMLBearer grant.
     */
    private boolean isSAML2BearerGrant(OAuth2AccessTokenReqDTO tokenReqDTO) {

        return SAML20_BEARER_GRANT_TYPE.equals(tokenReqDTO.getGrantType());
    }

    /**
     * Enable audit logger by default.
     *
     * @return true if config is not found or if enabled from config.
     */
    public boolean isEnabled() {

        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.
                readEventListenerProperty(AbstractIdentityHandler.class.getName(), this.getClass().getName());
        return identityEventListenerConfig == null || Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }
}
