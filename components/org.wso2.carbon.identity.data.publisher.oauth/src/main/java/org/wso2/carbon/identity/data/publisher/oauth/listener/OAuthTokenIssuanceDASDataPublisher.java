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

package org.wso2.carbon.identity.data.publisher.oauth.listener;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.data.publisher.oauth.OAuthDataPublisherConstants;
import org.wso2.carbon.identity.data.publisher.oauth.OAuthDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.oauth.internal.OAuthDataPublisherServiceHolder;
import org.wso2.carbon.identity.data.publisher.oauth.model.TokenData;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * Oauth Event Interceptor implemented for publishing oauth data to DAS
 */
public class OAuthTokenIssuanceDASDataPublisher extends AbstractOAuthEventInterceptor implements OAuthEventInterceptor {

    public static final Log LOG = LogFactory.getLog(OAuthTokenIssuanceDASDataPublisher.class);

    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) throws
            IdentityOAuth2Exception {

        TokenData tokenData = new TokenData();

        if (tokReqMsgCtx == null) {
            throw new IdentityOAuth2Exception("Empty token request message context");
        }
        AuthenticatedUser authorizedUser = tokReqMsgCtx.getAuthorizedUser();
        String[] publishingTenantDomains = null;

        if (authorizedUser != null) {
            tokenData.setIsSuccess(true);
            tokenData.setUser(authorizedUser.getUserName());
            tokenData.setUserStoreDomain(authorizedUser.getUserStoreDomain());
            tokenData.setTenantDomain(authorizedUser.getTenantDomain());
            publishingTenantDomains = OAuthDataPublisherUtils.getTenantDomains(tokenReqDTO.getTenantDomain(),
                    authorizedUser.getTenantDomain());
        }

        tokenData.setIssuedTime(tokReqMsgCtx.getAccessTokenIssuedTime());
        tokenData.setRefreshTokenValidityMillis(tokReqMsgCtx.getRefreshTokenvalidityPeriod());

        tokenData.setGrantType(tokenReqDTO.getGrantType());
        tokenData.setClientId(tokenReqDTO.getClientId());
        tokenData.setTokenId(tokenRespDTO.getTokenId());
        StringBuilder unauthzScopes = new StringBuilder();
        List<String> requestedScopes = new LinkedList(Arrays.asList(tokenReqDTO.getScope()));
        List<String> grantedScopes;
        if (tokenRespDTO.getAuthorizedScopes() != null && StringUtils.isNotBlank(tokenRespDTO.getAuthorizedScopes())) {
            grantedScopes = Arrays.asList(tokenRespDTO.getAuthorizedScopes().split(" "));
        } else {
            grantedScopes = Collections.emptyList();
        }
        requestedScopes.removeAll(grantedScopes);
        for (String scope : requestedScopes) {
            unauthzScopes.append(scope).append(" ");
        }

        // In a case if the authenticated user is not preset, publish event to sp tenant domain
        if (publishingTenantDomains == null) {
            publishingTenantDomains = OAuthDataPublisherUtils.getTenantDomains(tokenReqDTO.getTenantDomain(), null);
        }
        tokenData.setAuthzScopes(tokenRespDTO.getAuthorizedScopes());
        tokenData.setUnAuthzScopes(unauthzScopes.toString());
        tokenData.setAccessTokenValidityMillis(tokenRespDTO.getExpiresInMillis());
        HttpServletRequestWrapper tokenReq = tokenReqDTO.getHttpServletRequestWrapper();
        if (tokenReq != null) {
            tokenData.setRemoteIp(tokenReq.getRemoteAddr());
        }
        tokenData.addParameter(OAuthDataPublisherConstants.TENANT_ID, publishingTenantDomains);
        this.publishTokenIssueEvent(tokenData);
    }

    @Override
    public void onPostTokenIssue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, AccessTokenDO tokenDO,
                                 OAuth2AuthorizeRespDTO respDTO, Map<String, Object> params)
            throws IdentityOAuth2Exception {

        String[] publishingTenantDomains = null;
        StringBuilder unauthzScopes = new StringBuilder();
        AuthenticatedUser user = oauthAuthzMsgCtx.getAuthorizationReqDTO().getUser();
        TokenData tokenData = new TokenData();
        if (user == null || tokenDO == null) {
            tokenData.setIsSuccess(false);
            tokenData.setErrorCode(OAuth2ErrorCodes.SERVER_ERROR);
            tokenData.setErrorMsg("Error occurred when issuing token");
        }
        if (user != null) {
            tokenData.setUser(user.getUserName());
            tokenData.setUserStoreDomain(user.getUserStoreDomain());
            tokenData.setTenantDomain(user.getTenantDomain());

            if (oauthAuthzMsgCtx.getAuthorizationReqDTO() != null) {
                publishingTenantDomains = OAuthDataPublisherUtils.getTenantDomains(oauthAuthzMsgCtx
                        .getAuthorizationReqDTO().getTenantDomain(), user.getTenantDomain());
                HttpServletRequestWrapper authzRequest = oauthAuthzMsgCtx.getAuthorizationReqDTO()
                        .getHttpServletRequestWrapper();
                if (authzRequest != null) {
                    tokenData.setRemoteIp(authzRequest.getRemoteAddr());
                }
            } else {
                publishingTenantDomains = OAuthDataPublisherUtils.getTenantDomains(null, user.getTenantDomain());
            }

            tokenData.setIsSuccess(true);
        }
        if (tokenDO != null) {
            tokenData.setTokenId(tokenDO.getTokenId());
            tokenData.setGrantType(tokenDO.getGrantType());
            tokenData.setClientId(tokenDO.getConsumerKey());
            tokenData.setAccessTokenValidityMillis(tokenDO.getValidityPeriodInMillis());
            tokenData.setRefreshTokenValidityMillis(tokenDO.getRefreshTokenValidityPeriodInMillis());
            tokenData.setIssuedTime(tokenDO.getIssuedTime().getTime());
        }
        List<String> requestedScopes = new LinkedList(Arrays.asList(oauthAuthzMsgCtx.getAuthorizationReqDTO().
                getScopes()));
        List<String> grantedScopes = Arrays.asList(respDTO.getScope());
        requestedScopes.removeAll(grantedScopes);
        for (String scope : requestedScopes) {
            unauthzScopes.append(scope).append(" ");
        }
        tokenData.setAuthzScopes(OAuth2Util.buildScopeString(respDTO.getScope()));
        tokenData.setUnAuthzScopes(unauthzScopes.toString());
        // In a case if the authenticated user is not preset, publish event to sp tenant domain
        if (publishingTenantDomains == null && oauthAuthzMsgCtx.getAuthorizationReqDTO() != null) {
            publishingTenantDomains = OAuthDataPublisherUtils.getTenantDomains(oauthAuthzMsgCtx
                    .getAuthorizationReqDTO().getTenantDomain(), null);
        }

        tokenData.addParameter(OAuthDataPublisherConstants.TENANT_ID, publishingTenantDomains);
        this.publishTokenIssueEvent(tokenData);
    }

    @Override
    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                   OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) throws
            IdentityOAuth2Exception {

        //This will be treated same as a token issuance in refresh token grant
        onPostTokenIssue(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, params);
    }


    public void publishTokenIssueEvent(TokenData tokenData) {

        Object[] payloadData = new Object[15];
        payloadData[0] = tokenData.getUser();
        payloadData[1] = tokenData.getTenantDomain();
        payloadData[2] = tokenData.getUserStoreDomain();
        payloadData[3] = tokenData.getClientId();
        payloadData[4] = tokenData.getGrantType();
        payloadData[5] = tokenData.getTokenId();
        payloadData[6] = tokenData.getAuthzScopes();
        payloadData[7] = tokenData.getUnAuthzScopes();
        payloadData[8] = tokenData.isSuccess();
        payloadData[9] = tokenData.getErrorCode();
        payloadData[10] = tokenData.getErrorMsg();
        payloadData[11] = tokenData.getAccessTokenValidityMillis();
        payloadData[12] = tokenData.getRefreshTokenValidityMillis();
        payloadData[13] = tokenData.getIssuedTime();
        payloadData[14] = tokenData.getRemoteIp();

        String[] publishingDomains = (String[]) tokenData.getParameter(OAuthDataPublisherConstants.TENANT_ID);
        if (publishingDomains != null && publishingDomains.length > 0) {
            try {
                FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                for (String publishingDomain : publishingDomains) {
                    Object[] metadataArray = OAuthDataPublisherUtils.getMetaDataArray(publishingDomain);
                    Event event = new Event(OAuthDataPublisherConstants.TOKEN_ISSUE_EVENT_STREAM_NAME, System
                            .currentTimeMillis(), metadataArray, null, payloadData);
                    OAuthDataPublisherServiceHolder.getInstance().getPublisherService().publish(event);
                    if (LOG.isDebugEnabled() && event != null) {
                        LOG.debug("Sending out event : " + event.toString());
                    }
                }
            } finally {
                FrameworkUtils.endTenantFlow();
            }
        }
    }

    public String getName() {
        return OAuthDataPublisherConstants.OAUTH_TOKEN_ISSUANCE_DAS_DATA_PUBLISHER;
    }

}
