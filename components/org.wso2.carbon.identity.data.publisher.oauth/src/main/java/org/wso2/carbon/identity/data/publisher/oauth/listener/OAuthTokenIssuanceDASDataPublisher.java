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
import org.wso2.carbon.identity.data.publisher.oauth.OauthDataPublisherConstants;
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

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Oauth Event Interceptor implemented for publishing oauth data to DAS
 */
public class OAuthTokenIssuanceDASDataPublisher extends AbstractOAuthEventInterceptor implements OAuthEventInterceptor {

    private EventStreamService publisher;

    public OAuthTokenIssuanceDASDataPublisher() {
        publisher = OAuthDataPublisherServiceHolder.getInstance().getPublisherService();
    }


    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        TokenData tokenData = new TokenData();

        AuthenticatedUser authorizedUser = tokReqMsgCtx.getAuthorizedUser();
        if (authorizedUser != null) {
            tokenData.setUser(authorizedUser.getUserName());
            tokenData.setUserStoreDomain(authorizedUser.getUserStoreDomain());
            tokenData.setTenantDomain(authorizedUser.getTenantDomain());
        }
        tokenData.setGrantType(tokenReqDTO.getGrantType());
        tokenData.setClientId(tokenReqDTO.getClientId());
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
        tokenData.setAuthzScopes(authzScopes.toString());
        tokenData.setUnAuthzScopes(unauthzScopes.toString());
        this.publishTokenIssueEvent(tokenData);
    }

    @Override
    public void onPostTokenIssue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, AccessTokenDO tokenDO,
                                 OAuth2AuthorizeRespDTO respDTO)
            throws IdentityOAuth2Exception {

        String username = null;
        StringBuilder authzScopes = new StringBuilder();
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
        }
        if (tokenDO != null) {
            tokenData.setTokenId(tokenDO.getTokenId());
            tokenData.setGrantType(tokenDO.getGrantType());
            tokenData.setClientId(tokenDO.getConsumerKey());
            tokenData.setAccessTokenValidityMillis(tokenDO.getValidityPeriodInMillis());
            tokenData.setRefreshTokenValidityMillis(tokenDO.getRefreshTokenValidityPeriodInMillis());
            tokenData.setIssuedTime(tokenDO.getIssuedTime().getTime());
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
        this.publishTokenIssueEvent(tokenData);

    }

    @Override
    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                   OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        //This will be treated same as a token issuance in refresh token grant
        onPostTokenIssue(tokenReqDTO, tokenRespDTO, tokReqMsgCtx);
    }


    public void publishTokenIssueEvent(TokenData tokenData) {

        Object[] payloadData = new Object[14];
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
        Event event = new Event(OauthDataPublisherConstants.TOKEN_ISSUE_EVENT_STREAM_NAME, System.currentTimeMillis()
                , null, null, payloadData);
        publisher.publish(event);
    }

    public String getName() {
        return OauthDataPublisherConstants.OAUTH_TOKEN_ISSUANCE_DAS_DATA_PUBLISHER;
    }

}
