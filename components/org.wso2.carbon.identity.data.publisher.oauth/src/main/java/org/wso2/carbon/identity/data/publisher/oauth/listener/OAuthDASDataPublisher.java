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
import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.data.publisher.oauth.OauthDataPublisherConstants;
import org.wso2.carbon.identity.data.publisher.oauth.internal.OAuthDataPublisherServiceHolder;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Oauth Event Interceptor implemented for publishing oauth data to DAS
 */
public class OAuthDASDataPublisher extends AbstractIdentityHandler implements OAuthEventInterceptor {

    private EventStreamService publisher;

    public OAuthDASDataPublisher() {
        publisher = OAuthDataPublisherServiceHolder.getInstance().getPublisherService();
    }

    @Override
    public void onPreTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        //Not needed
    }

    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return;
        }
        String username = null;
        String userstoreDomain = null;
        String tenantDomain = null;
        String grantType;
        String clientId;
        AuthenticatedUser authorizedUser = tokReqMsgCtx.getAuthorizedUser();
        if (authorizedUser != null) {
            username = authorizedUser.getUserName();
            userstoreDomain = authorizedUser.getUserStoreDomain();
            tenantDomain = authorizedUser.getTenantDomain();
        }
        grantType = tokenReqDTO.getGrantType();
        clientId = tokenReqDTO.getClientId();
        String tokenId = tokenRespDTO.getTokenId();
        StringBuilder authzScopes = new StringBuilder();
        StringBuilder unauthzScopes = new StringBuilder();
        List<String> requestedScopes = new LinkedList(Arrays.asList(tokenReqDTO.getScope()));
        List<String> grantedScopes;
        if (tokenRespDTO.getAuthorizedScopes() != null && StringUtils.isNotBlank(tokenRespDTO.getAuthorizedScopes())) {
            grantedScopes = Arrays.asList(tokenRespDTO.getAuthorizedScopes().split(" "));
        } else {
            grantedScopes = Collections.emptyList();
        }
        for (String scope : grantedScopes) {
            authzScopes.append(scope).append(" ");
        }
        requestedScopes.removeAll(grantedScopes);
        for (String scope : requestedScopes) {
            unauthzScopes.append(scope).append(" ");
        }

        this.publishTokenIssueEvent(username, tenantDomain, userstoreDomain, clientId, grantType, tokenId,
                authzScopes.toString(), unauthzScopes.toString(), !tokenRespDTO.isError(), tokenRespDTO.getErrorCode(),
                tokenRespDTO.getErrorMsg(), tokReqMsgCtx.getValidityPeriod(),
                tokReqMsgCtx.getRefreshTokenvalidityPeriod(), tokReqMsgCtx.getAccessTokenIssuedTime());
    }

    @Override
    public void onPreTokenIssue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {
        //Not needed
    }

    @Override
    public void onPostTokenIssue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, AccessTokenDO tokenDO,
                                 OAuth2AuthorizeRespDTO respDTO)
            throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return;
        }
        String username = null;
        String userstoreDomain = null;
        String tenantDomain = null;
        String grantType = null;
        String clientId = null;
        String tokenId = null;
        boolean isSuccess = true;
        StringBuilder authzScopes = new StringBuilder();
        StringBuilder unauthzScopes = new StringBuilder();
        AuthenticatedUser user = oauthAuthzMsgCtx.getAuthorizationReqDTO().getUser();
        String errorCode = null;
        String errorMsg = null;
        long tokenValidity = 0;
        long refreshTokenValidity = 0;
        long issuedTime = 0;
        if (user == null || tokenDO == null) {
            isSuccess = false;
            errorCode = OAuth2ErrorCodes.SERVER_ERROR;
            errorMsg = "Error occurred when issuing token";
        }
        if (user != null) {
            username = user.getUserName();
            userstoreDomain = user.getUserStoreDomain();
            tenantDomain = user.getTenantDomain();
        }
        if (tokenDO != null) {
            tokenId = tokenDO.getTokenId();
            grantType = tokenDO.getGrantType();
            clientId = tokenDO.getConsumerKey();
            tokenValidity = tokenDO.getValidityPeriodInMillis();
            refreshTokenValidity = tokenDO.getRefreshTokenValidityPeriodInMillis();
            issuedTime = tokenDO.getIssuedTime().getTime();
        }
        List<String> requestedScopes = Arrays.asList(oauthAuthzMsgCtx.getAuthorizationReqDTO().getScopes());
        List<String> grantedScopes = Arrays.asList(respDTO.getScope());
        for (String scope : grantedScopes) {
            authzScopes.append(scope).append(" ");
        }
        requestedScopes.removeAll(grantedScopes);
        for (String scope : requestedScopes) {
            unauthzScopes.append(scope).append(" ");
        }
        this.publishTokenIssueEvent(username, tenantDomain, userstoreDomain, clientId, grantType, tokenId,
                authzScopes.toString(), unauthzScopes.toString(), isSuccess, errorCode, errorMsg, tokenValidity,
                refreshTokenValidity, issuedTime);

    }

    @Override
    public void onPreTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        //Not needed
    }

    @Override
    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                   OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        if (!isEnabled()) {
            return;
        }
        //This will be treated same as a token issuance in refresh token grant
        onPostTokenIssue(tokenReqDTO, tokenRespDTO, tokReqMsgCtx);
    }

    @Override
    public void onPreTokenRevocationByClient(OAuthRevocationRequestDTO revokeRequestDTO)
            throws IdentityOAuth2Exception {

    }

    @Override
    public void onPostTokenRevocationByClient(OAuthRevocationRequestDTO revokeRequestDTO,
                                              OAuthRevocationResponseDTO revokeResponseDTO, AccessTokenDO accessTokenDO,
                                              RefreshTokenValidationDataDO refreshTokenDO)
            throws IdentityOAuth2Exception {
        if (!isEnabled()) {
            return;
        }
        String clientId = null;
        boolean isFailed = false;
        String errorMsg = null;
        String errorCode = null;
        String tokenId = null;
        if (revokeRequestDTO != null) {
            clientId = revokeRequestDTO.getConsumerKey();
        }
        if (revokeResponseDTO != null) {
            isFailed = revokeResponseDTO.isError();
            errorMsg = revokeResponseDTO.getErrorMsg();
            errorCode = revokeResponseDTO.getErrorCode();
        }
        if (accessTokenDO != null) {
            tokenId = accessTokenDO.getTokenId();
        }
        this.publishTokenRevocationEvent(clientId, !isFailed, errorMsg, errorCode, tokenId, "CLIENT");


    }

    @Override
    public void onPreTokenRevocationByResourceOwner(
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO revokeRequestDTO)
            throws IdentityOAuth2Exception {

    }

    @Override
    public void onPostTokenRevocationByResourceOwner(
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO revokeRequestDTO,
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationResponseDTO revokeRespDTO,
            AccessTokenDO accessTokenDO) throws IdentityOAuth2Exception {
        if (!isEnabled()) {
            return;
        }
        String clientId = null;
        boolean isFailed = false;
        String errorMsg = null;
        String errorCode = null;
        String tokenId = null;
        if (revokeRequestDTO != null) {
            clientId = revokeRequestDTO.getConsumerKey();
        }
        if (revokeRespDTO != null) {
            isFailed = revokeRespDTO.isError();
            errorMsg = revokeRespDTO.getErrorMsg();
            errorCode = revokeRespDTO.getErrorCode();
        }
        if (accessTokenDO != null) {
            tokenId = accessTokenDO.getTokenId();
        }

        this.publishTokenRevocationEvent(clientId, !isFailed, errorMsg, errorCode, tokenId, "RESOURCE_OWNER");

    }

    @Override
    public void onPreTokenValidation(OAuth2TokenValidationRequestDTO validationReqDTO) throws IdentityOAuth2Exception {

    }

    @Override
    public void onPostTokenValidation(OAuth2TokenValidationRequestDTO validationReqDTO,
                                      OAuth2TokenValidationResponseDTO validationResponseDTO)
            throws IdentityOAuth2Exception {

    }

    public String getName() {
        return OauthDataPublisherConstants.OAUTH_DAS_DATA_PUBLISHER;
    }

    public void publishTokenIssueEvent(String user, String tenantDomain, String userstoreDomain, String clientId,
                                       String grantType, String tokenId, String authzScopes, String unAuthzScopes,
                                       boolean isSuccess, String errorCode, String errorMsg,
                                       long accessTokenValidityMillis, long refreshTokenValidityMillis,
                                       long issuedTime) {

        Object[] payloadData = new Object[14];
        payloadData[0] = user;
        payloadData[1] = tenantDomain;
        payloadData[2] = userstoreDomain;
        payloadData[3] = clientId;
        payloadData[4] = grantType;
        payloadData[5] = tokenId;
        payloadData[6] = authzScopes;
        payloadData[7] = unAuthzScopes;
        payloadData[8] = isSuccess;
        payloadData[9] = errorCode;
        payloadData[10] = errorMsg;
        payloadData[11] = accessTokenValidityMillis;
        payloadData[12] = refreshTokenValidityMillis;
        payloadData[13] = issuedTime;
        Event event = new Event(OauthDataPublisherConstants.TOKEN_ISSUE_EVENT_STREAM_NAME, System.currentTimeMillis()
                , null, null, payloadData);
        publisher.publish(event);
    }


    public void publishTokenRevocationEvent(String clientId, boolean isSuccess,
                                            String errorMsg, String errorCode, String tokenId, String revokedBy) {
//
//        Object[] payloadData = new Object[6];
//        payloadData[0] = clientId;
//        payloadData[1] = isSuccess;
//        payloadData[2] = errorMsg;
//        payloadData[3] = errorCode;
//        payloadData[4] = tokenId;
//        payloadData[5] = revokedBy;
//        Event event = new Event(OauthDataPublisherConstants.TOKEN_REVOKE_EVENT_STREAM_NAME, System
// .currentTimeMillis(), null, null, payloadData);
//        publisher.publish(event);
    }

}
