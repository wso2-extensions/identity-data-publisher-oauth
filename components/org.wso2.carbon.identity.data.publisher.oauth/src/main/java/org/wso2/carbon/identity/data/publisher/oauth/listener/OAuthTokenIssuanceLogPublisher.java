/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.data.publisher.oauth.listener;

import com.google.gson.Gson;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.Map;

import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
 * This class logs token generation related information.
 */
public class OAuthTokenIssuanceLogPublisher extends AbstractOAuthEventInterceptor implements OAuthEventInterceptor {

    private static final Log TRANSACTION_LOG = LogFactory.getLog("TRANSACTION_LOGGER");
    private static final Log LOG = LogFactory.getLog(OAuthTokenIssuanceLogPublisher.class);
    private static final String PROP_CLIENT_ID = "client_id";
    private static final String PROP_GRANT_TYPE = "grant_type";
    private static final String PROP_SCOPE = "scope";
    private static final String PROP_USER = "user";
    private static final String PROP_ERROR = "error";
    private static final String PROP_ERROR_DESCRIPTION = "error_description";
    private static final String PROP_ISSUED_TIME = "issued_time";
    private static final String PROP_TIME_TAKEN_IN_MILLIS = "time_taken_in_millis";
    private static final String PROP_EXPIRES_IN_SECONDS = "expires_in_seconds";
    private static final String PROP_SUCCESS = "success";
    private static final String LOG_INFO_TYPE_TOKEN = "OAUTH TOKEN";
    private static final String NOT_AVAILABLE = "N/A";
    private static final String TRANSACTION_LOG_FORMAT = "Type: %s | Info: %s";
    private static final String LOG_INFO_TYPE_INTROSPECTION = "OAUTH INTROSPECTION";
    private static final String PROP_TYPE = "type";
    private static final String TYPE_OAUTH = "oauth";
    private static final String TYPE_INTROSPECTION = "introspection";
    private static final String PROP_LOG_TOKEN = "Log.Token";
    private static final String PROP_TOKEN = "token";

    private static boolean isTokenLoggable;
    private static ThreadLocal<Long> startTime = new ThreadLocal<>();

    public OAuthTokenIssuanceLogPublisher() {

        super.init(initConfig);
        String isTokenLoggableProperty = this.properties.getProperty(PROP_LOG_TOKEN);
        isTokenLoggable = StringUtils.isNotEmpty(isTokenLoggableProperty) &&
                Boolean.parseBoolean(isTokenLoggableProperty);
    }

    public void onPreTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                Map<String, Object> params) throws IdentityOAuth2Exception {

        startTime.remove();
        startTime.set(System.currentTimeMillis());
    }

    public void onPreTokenIssue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, Map<String, Object> params) throws
            IdentityOAuth2Exception {

        startTime.remove();
        startTime.set(System.currentTimeMillis());
    }

    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) throws
            IdentityOAuth2Exception {

        try {
            String jsonInfo = getJsonInfoForPostTokenIssue(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, params);
            logTransactionInfo(jsonInfo, LOG_INFO_TYPE_TOKEN);
        } catch (Throwable e) {
            // Catching a throwable as we do no need to interrupt the code flow since these are logging operations.
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error occurred while logging token information.", e);
            }
        } finally {
            startTime.remove();
        }
    }

    @Override
    public void onPostTokenIssue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, AccessTokenDO tokenDO,
                                 OAuth2AuthorizeRespDTO respDTO, Map<String, Object> params)
            throws IdentityOAuth2Exception {

        try {
            long expiresIn = respDTO.getValidityPeriod();
            long accessTokenIssuedTime = 0;
            if (tokenDO.getIssuedTime() != null) {
                accessTokenIssuedTime = tokenDO.getIssuedTime().getTime();
            }
            String clientId = tokenDO.getConsumerKey();
            String grantType = tokenDO.getGrantType();
            String[] scope = tokenDO.getScope();
            String scopeString = StringUtils.join(scope, ' ');

            String user;
            AuthenticatedUser authorizedUser = tokenDO.getAuthzUser();
            if (authorizedUser != null) {
                user = authorizedUser.getUsernameAsSubjectIdentifier(true, true);
            } else {
                user = NOT_AVAILABLE;
            }
            if (LoggerUtils.isLogMaskingEnable && StringUtils.isNotBlank(user) && !user.equals(NOT_AVAILABLE)) {
                user = LoggerUtils.getMaskedContent(user);
            }
            Map<String, Object> infoParams = new HashMap<>();
            Gson gson = new Gson();

            infoParams.put(PROP_TYPE, TYPE_OAUTH);
            addStringToMap(PROP_CLIENT_ID, clientId, infoParams);
            addStringToMap(PROP_GRANT_TYPE, grantType, infoParams);
            addStringToMap(PROP_SCOPE, scopeString, infoParams);
            addStringToMap(PROP_USER, user, infoParams);
            if (isNotBlank(respDTO.getErrorCode()) || isNotBlank(respDTO.getErrorMsg())) {
                infoParams.put(PROP_SUCCESS, false);
                addStringToMap(PROP_ERROR, respDTO.getErrorCode(), infoParams);
                addStringToMap(PROP_ERROR_DESCRIPTION, respDTO.getErrorMsg(), infoParams);
            } else {
                infoParams.put(PROP_SUCCESS, true);
                infoParams.put(PROP_ISSUED_TIME, accessTokenIssuedTime);
                infoParams.put(PROP_EXPIRES_IN_SECONDS, expiresIn);
                long timeTaken = System.currentTimeMillis() - startTime.get();
                infoParams.put(PROP_TIME_TAKEN_IN_MILLIS, timeTaken);
            }

            logTransactionInfo(gson.toJson(infoParams), LOG_INFO_TYPE_TOKEN);
        } catch (Throwable e) {
            // Catching a throwable as we do no need to interrupt the code flow since these are logging operations.
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error occurred while logging token information.", e);
            }
        } finally {
            startTime.remove();
        }
    }

    @Override
    public void onPreTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                  Map<String, Object> params) throws IdentityOAuth2Exception {

        startTime.remove();
        startTime.set(System.currentTimeMillis());
    }

    @Override
    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                   OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params)
            throws IdentityOAuth2Exception {

        try {
            String jsonInfo = getJsonInfoForPostTokenIssue(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, params);
            logTransactionInfo(jsonInfo, LOG_INFO_TYPE_TOKEN);
        } catch (Throwable e) {
            // Catching a throwable as we do no need to interrupt the code flow since these are logging operations.
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error occurred while logging token information.", e);
            }
        } finally {
            startTime.remove();
        }
    }

    private String getJsonInfoForPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                                OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) {

        long accessTokenIssuedTime = tokReqMsgCtx.getAccessTokenIssuedTime();
        long expiresIn = tokenRespDTO.getExpiresIn();
        String clientId = tokenReqDTO.getClientId();
        String grantType = tokenReqDTO.getGrantType();

        String[] scope = tokenReqDTO.getScope();
        String scopeString = StringUtils.join(scope, ' ');
        String resourceOwner = tokenReqDTO.getResourceOwnerUsername();

        String user;
        AuthenticatedUser authorizedUser = tokReqMsgCtx.getAuthorizedUser();
        if (authorizedUser != null) {
            user = authorizedUser.getUsernameAsSubjectIdentifier(true, true);
        } else if (StringUtils.isNotBlank(resourceOwner)){

            String tenantDomain = tokenReqDTO.getTenantDomain();
            if (StringUtils.isNotBlank(tenantDomain)) {
                user = UserCoreUtil.addTenantDomainToEntry(resourceOwner, tenantDomain);
            } else {
                user = resourceOwner;
            }
        } else {
            user = NOT_AVAILABLE;
        }
        if (LoggerUtils.isLogMaskingEnable && StringUtils.isNotBlank(user) && !user.equals(NOT_AVAILABLE)) {
            user = LoggerUtils.getMaskedContent(user);
        }
        Map<String, Object> infoParams = new HashMap<>();
        Gson gson = new Gson();

        infoParams.put(PROP_TYPE, TYPE_OAUTH);
        addStringToMap(PROP_CLIENT_ID, clientId, infoParams);
        addStringToMap(PROP_GRANT_TYPE, grantType, infoParams);
        addStringToMap(PROP_SCOPE, scopeString, infoParams);
        addStringToMap(PROP_USER, user, infoParams);
        if (tokenRespDTO.isError()) {
            addStringToMap(PROP_ERROR, tokenRespDTO.getErrorCode(), infoParams);
            addStringToMap(PROP_ERROR_DESCRIPTION, tokenRespDTO.getErrorMsg(), infoParams);
            infoParams.put(PROP_SUCCESS, false);
        } else {
            infoParams.put(PROP_ISSUED_TIME, accessTokenIssuedTime);
            infoParams.put(PROP_EXPIRES_IN_SECONDS, expiresIn);
            infoParams.put(PROP_SUCCESS, true);
            long timeTaken = System.currentTimeMillis() - startTime.get();
            infoParams.put(PROP_TIME_TAKEN_IN_MILLIS, timeTaken);
        }
        return gson.toJson(infoParams);
    }

    @Override
    public void onTokenIssueException(Throwable throwable, Map<String, Object> params) throws IdentityOAuth2Exception {

        try {
            params.put(PROP_SUCCESS, false);
            params.put(PROP_TYPE, TYPE_OAUTH);
            Gson gson = new Gson();
            logTransactionInfo(gson.toJson(params), LOG_INFO_TYPE_TOKEN);
        } catch (Throwable e) {
            // Catching a throwable as we do no need to interrupt the code flow since these are logging operations.
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error occurred while logging token error information.", e);
            }
        } finally {
            startTime.remove();
        }
    }

    private void addStringToMap(String name, String value, Map<String, Object> params) {

        if (isNotBlank(value)) {
            params.put(name, value);
        }
    }

    /**
     * Printing the log for given log info type.
     *
     * @param info        Information to log.
     * @param logInfoType Type of log.
     */
    private void logTransactionInfo(String info, String logInfoType) {

        String transactionEntry = String.format(TRANSACTION_LOG_FORMAT, logInfoType, info);
        TRANSACTION_LOG.info(transactionEntry);
    }

    @Override
    public void onPreTokenValidation(OAuth2TokenValidationRequestDTO validationReqDTO, Map<String, Object> params)
            throws IdentityOAuth2Exception {

        startTime.remove();
        startTime.set(System.currentTimeMillis());
    }

    @Override
    public void onPostTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO,
                                      OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO,
                                      Map<String, Object> params) throws IdentityOAuth2Exception {

        try {
            String jsonInfo = getJsonInfoForPostTokenValidation(oAuth2TokenValidationRequestDTO,
                    oAuth2IntrospectionResponseDTO, params);
            logTransactionInfo(jsonInfo, LOG_INFO_TYPE_INTROSPECTION);
        } catch (Throwable e) {
            // Catching a throwable as we do no need to interrupt the code flow since these are logging operations.
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error occurred while logging token introspection information.", e);
            }
        } finally {
            startTime.remove();
        }
    }

    /**
     * Return json format string to print the log.
     *
     * @param oAuth2TokenValidationRequestDTO
     * @param oAuth2IntrospectionResponseDTO
     * @param params
     * @return
     */
    protected String getJsonInfoForPostTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO,
                                                       OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO,
                                                       Map<String, Object> params) {

        Gson gson = new Gson();
        Map<String, Object> infoParams = new HashMap<>();

        if (oAuth2IntrospectionResponseDTO.isActive()) {
            long expiresIn = oAuth2IntrospectionResponseDTO.getExp() - System.currentTimeMillis() / 1000L;
            long issuedAt = oAuth2IntrospectionResponseDTO.getIat();
            String scope = oAuth2IntrospectionResponseDTO.getScope();
            String clientId = oAuth2IntrospectionResponseDTO.getClientId();
            String username = oAuth2IntrospectionResponseDTO.getUsername();
            if (LoggerUtils.isLogMaskingEnable && StringUtils.isNotBlank(username)) {
                username = LoggerUtils.getMaskedContent(username);
            }
            OAuth2TokenValidationMessageContext oAuth2TokenValidationMessageContext =
                    (OAuth2TokenValidationMessageContext) oAuth2IntrospectionResponseDTO.getProperties().
                            get("OAuth2TokenValidationMessageContext");
            AccessTokenDO accessTokenDO =
                    (AccessTokenDO) oAuth2TokenValidationMessageContext.getProperty("AccessTokenDO");
            String grantType = accessTokenDO.getGrantType();

            infoParams.put(PROP_SUCCESS, true);
            infoParams.put(PROP_EXPIRES_IN_SECONDS, expiresIn);
            infoParams.put(PROP_ISSUED_TIME, issuedAt);
            addStringToMap(PROP_SCOPE, scope, infoParams);
            addStringToMap(PROP_CLIENT_ID, clientId, infoParams);
            addStringToMap(PROP_USER, username, infoParams);
            addStringToMap(PROP_GRANT_TYPE, grantType, infoParams);
        } else {
            infoParams.put(PROP_SUCCESS, false);
            addStringToMap(PROP_ERROR, oAuth2IntrospectionResponseDTO.getError(), infoParams);
        }

        if (isTokenLoggable) {
            addStringToMap(PROP_TOKEN, oAuth2TokenValidationRequestDTO.getAccessToken().getIdentifier(),
                    infoParams);
        }
        infoParams.put(PROP_TYPE, TYPE_INTROSPECTION);
        long timeTaken = System.currentTimeMillis() - startTime.get();
        infoParams.put(PROP_TIME_TAKEN_IN_MILLIS, timeTaken);
        return gson.toJson(infoParams);
    }

    @Override
    public void onTokenValidationException(OAuth2TokenValidationRequestDTO introspectionRequest,
                                           Map<String, Object> params) throws IdentityOAuth2Exception {

        try {
            params.put(PROP_TYPE, TYPE_INTROSPECTION);
            params.put(PROP_SUCCESS, false);
            if (isTokenLoggable && introspectionRequest != null) {
                addStringToMap(PROP_TOKEN, introspectionRequest.getAccessToken().getIdentifier(),
                        params);
            }
            if (startTime.get() != null) {
                long timeTaken = System.currentTimeMillis() - startTime.get();
                params.put(PROP_TIME_TAKEN_IN_MILLIS, timeTaken);
            }
            Gson gson = new Gson();
            logTransactionInfo(gson.toJson(params), LOG_INFO_TYPE_INTROSPECTION);
        } catch (Throwable e) {
            // Catching a throwable as we do no need to interrupt the code flow since these are logging operations.
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error occurred while logging token introspection error information.", e);
            }
        } finally {
            startTime.remove();
        }
    }
}
