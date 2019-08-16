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
import org.wso2.carbon.identity.data.publisher.oauth.OAuthDataPublisherUtils;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;

import java.util.Map;
import java.sql.Timestamp;

/**
 * Audit logger for Token Revocation.
 */
public class TokenRevocationAuditLogger extends AbstractOAuthEventInterceptor {

    private static final Log AUDIT_LOG = LogFactory.getLog("AUDIT_LOG");
    public static final int MILLIS_TO_SECONDS_FACTOR = 1000;
    private static final Log log = LogFactory.getLog(TokenRevocationAuditLogger.class);

    public TokenRevocationAuditLogger() {
        super();
    }

    @Override
    public void onPostTokenRevocationByClient(OAuthRevocationRequestDTO revokeRequestDTO,
                                              OAuthRevocationResponseDTO revokeResponseDTO, AccessTokenDO accessTokenDO,
                                              RefreshTokenValidationDataDO refreshTokenDO, Map<String, Object> params)
            throws IdentityOAuth2Exception {

        String authenticatedSubjectIdentifier = "N/A";
        String authenticatedUserStoreDomain = "N/A";
        String authenticatedUserTenantDomain = "N/A";
        String tokenType = "N/A";
        String auditResult;
        String requestInitiator  = "N/A";
        String activeDuration = "N/A";

        Timestamp issuedTime = null;
        Timestamp revokedTime = new Timestamp(System.currentTimeMillis());

        if (StringUtils.isNotEmpty(revokeRequestDTO.getToken_type())) {
            tokenType = revokeRequestDTO.getToken_type();
        }

        if (revokeResponseDTO.isError()) {
            auditResult = FrameworkConstants.AUDIT_FAILED;
        } else {
            auditResult = FrameworkConstants.AUDIT_SUCCESS;

            if (refreshTokenDO != null && refreshTokenDO.getAuthorizedUser() != null) {
                authenticatedSubjectIdentifier = refreshTokenDO.getAuthorizedUser().getAuthenticatedSubjectIdentifier();
                authenticatedUserTenantDomain = refreshTokenDO.getAuthorizedUser().getTenantDomain();
                authenticatedUserStoreDomain = refreshTokenDO.getAuthorizedUser().getUserStoreDomain();
                requestInitiator = refreshTokenDO.getAuthorizedUser().toString();
                issuedTime = refreshTokenDO.getIssuedTime();
            } else if (accessTokenDO != null && accessTokenDO.getAuthzUser() != null) {
                authenticatedSubjectIdentifier = accessTokenDO.getAuthzUser().getAuthenticatedSubjectIdentifier();
                authenticatedUserTenantDomain = accessTokenDO.getAuthzUser().getTenantDomain();
                authenticatedUserStoreDomain = accessTokenDO.getAuthzUser().getUserStoreDomain();
                requestInitiator = accessTokenDO.getAuthzUser().toString();
                issuedTime = accessTokenDO.getIssuedTime();
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Unknown token in revocation request for client id: "
                            + revokeRequestDTO.getConsumerKey());
                }
            }

            if (issuedTime != null) {
                long activePeriodInMillis = revokedTime.getTime() - issuedTime.getTime();
                activeDuration = activePeriodInMillis / MILLIS_TO_SECONDS_FACTOR + "s";
            }
        }
        String serviceProvider = getServiceProvider(revokeRequestDTO);

        String auditData = "\"" + "AuthenticatedUser" + "\" : \"" + authenticatedSubjectIdentifier
                + "\", \"" + "AuthenticatedUserStoreDomain" + "\" : \"" + authenticatedUserStoreDomain
                + "\", \"" + "AuthenticatedUserTenantDomain" + "\" : \"" + authenticatedUserTenantDomain
                + "\", \"" + "ServiceProvider" + "\" : \"" + serviceProvider
                + "\", \"" + "TokenType" + "\" : \"" + tokenType
                + "\", \"" + "ActiveDuration" + "\" : \"" + activeDuration
                + "\", \"" + "RelyingParty" + "\" : \"" + revokeRequestDTO.getConsumerKey()
                + "\"";

        AUDIT_LOG.info(String.format(FrameworkConstants.AUDIT_MESSAGE,
                requestInitiator,
                "PostTokenRevocationByClient",
                "TokenRevocationAuditLogger",
                auditData,
                auditResult
                )
        );
    }

    /**
     * This method retrieves the service provider name using client Id information
     * available in OAuthRevocationRequestDTO
     *
     * @param revokeRequestDTO
     * @return
     * @throws IdentityOAuth2Exception
     */
    private String getServiceProvider(OAuthRevocationRequestDTO revokeRequestDTO) throws IdentityOAuth2Exception {

        String serviceProvider = "N/A";
        try {
            OAuthAppDO oAuthAppDO = OAuthDataPublisherUtils.getApplication(revokeRequestDTO.getConsumerKey());
            if (oAuthAppDO != null && oAuthAppDO.getUser() != null) {
                serviceProvider = oAuthAppDO.getApplicationName();
            }
        } catch (InvalidOAuthClientException e) {
            log.error("Error while retrieving oauth application.");
            if (log.isDebugEnabled()) {
                log.debug(e);
            }
        }
        return serviceProvider;
    }
}
