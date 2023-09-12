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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Map;

/**
 * Audit logger for Refresh token request flow.
 */
public class RefreshTokenGrantAuditLogger extends AbstractOAuthEventInterceptor {

    private static final Log AUDIT_LOG = LogFactory.getLog("AUDIT_LOG");

    public RefreshTokenGrantAuditLogger() {
        super();
    }

    @Override
    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                   OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params)
            throws IdentityOAuth2Exception {

        String requestType = "N/A";
        String serviceProvider = "N/A";
        String authenticatedSubjectIdentifier = "N/A";
        String authenticatedUserStoreDomain = "N/A";
        String authenticatedUserTenantDomain = "N/A";
        String requestInitiator = null;
        String auditResult;

        if (tokReqMsgCtx.getProperty("OAuthAppDO") instanceof OAuthAppDO) {
            OAuthAppDO oAuthAppDO = (OAuthAppDO) tokReqMsgCtx.getProperty("OAuthAppDO");
            requestType = getRequestType(tokReqMsgCtx);
            serviceProvider = oAuthAppDO.getApplicationName();
        }

        if (isTokenRequestSuccessful(tokReqMsgCtx)) {
            requestInitiator = tokReqMsgCtx.getAuthorizedUser().toString();
            authenticatedSubjectIdentifier = tokReqMsgCtx.getAuthorizedUser().getLoggableMaskedUserId();
            authenticatedUserStoreDomain = tokReqMsgCtx.getAuthorizedUser().getUserStoreDomain();
            authenticatedUserTenantDomain = tokReqMsgCtx.getAuthorizedUser().getTenantDomain();
            auditResult = FrameworkConstants.AUDIT_SUCCESS;
        } else {
            auditResult = FrameworkConstants.AUDIT_FAILED;
        }

        String auditData = "\"" + "AuthenticatedUser" + "\" : \"" + authenticatedSubjectIdentifier
                + "\", \"" + "AuthenticatedUserStoreDomain" + "\" : \"" + authenticatedUserStoreDomain
                + "\", \"" + "AuthenticatedUserTenantDomain" + "\" : \"" + authenticatedUserTenantDomain
                + "\", \"" + "ServiceProvider" + "\" : \"" + serviceProvider
                + "\", \"" + "RequestType" + "\" : \"" + requestType
                + "\", \"" + "RelyingParty" + "\" : \"" + tokenReqDTO.getClientId()
                + "\"";

        AUDIT_LOG.info(String.format(FrameworkConstants.AUDIT_MESSAGE,
                requestInitiator,
                "PostTokenRenewal",
                "RefreshTokenGrantAuditLogger",
                auditData,
                auditResult
                )
        );
    }

    private String getRequestType(OAuthTokenReqMessageContext tokReqMsgCtx) {
        boolean isOpenIdConnect = OAuth2Util.isOIDCAuthzRequest(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
        return isOpenIdConnect ? FrameworkConstants.OIDC : FrameworkConstants.OAUTH2;
    }

    private boolean isTokenRequestSuccessful(OAuthTokenReqMessageContext tokReqMsgCtx) {
        // If the request was successful we will have a valid authorized user set in the token context.
        return tokReqMsgCtx.getAuthorizedUser() != null;
    }
}
