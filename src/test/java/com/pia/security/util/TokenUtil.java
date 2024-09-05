package com.pia.security.util;

import lombok.experimental.UtilityClass;

@UtilityClass
public class TokenUtil {

  /**
   * <pre>
   *   {
   *   "exp": 1725524373,
   *   "iat": 1725520773,
   *   "jti": "c62aed73-f6c7-4597-9e40-18b74bd1cb2c",
   *   "iss": "http://localhost:8000/realms/rehearsal-realm",
   *   "aud": [
   *     "realm-management",
   *     "account"
   *   ],
   *   "sub": "a6d5a538-62c6-4dba-a28a-2cd380381c2c",
   *   "typ": "Bearer",
   *   "azp": "backend_clients",
   *   "sid": "b3c0aaa7-6132-418e-8413-4b17c8d5c164",
   *   "acr": "1",
   *   "allowed-origins": [
   *     ""
   *   ],
   *   "realm_access": {
   *     "roles": [
   *       "offline_access",
   *       "default-roles-rehearsal-realm",
   *       "uma_authorization"
   *     ]
   *   },
   *   "resource_access": {
   *     "realm-management": {
   *       "roles": [
   *         "view-users",
   *         "query-groups",
   *         "query-users"
   *       ]
   *     },
   *     "account": {
   *       "roles": [
   *         "manage-account",
   *         "manage-account-links",
   *         "view-profile"
   *       ]
   *     },
   *     "backend_clients": {
   *       "roles": [
   *         "read"
   *       ]
   *     }
   *   },
   *   "scope": "openid profile email",
   *   "email_verified": true,
   *   "name": "Reader Reader",
   *   "groups": [
   *     "read"
   *   ],
   *   "preferred_username": "reader@pia-team.com",
   *   "given_name": "Reader",
   *   "family_name": "Reader",
   *   "email": "reader@pia-team.com"
   * }
   * </pre>>
   */
  public static final String EXPIRED_READER_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJCdTVuVzFrTkRCeUtDc01nLUFDdEgwNVpiSnk0SDdycEVWR1MzZ2NXWV9ZIn0.eyJleHAiOjE3MjU1MjQzNzMsImlhdCI6MTcyNTUyMDc3MywianRpIjoiYzYyYWVkNzMtZjZjNy00NTk3LTllNDAtMThiNzRiZDFjYjJjIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDAwL3JlYWxtcy9yZWhlYXJzYWwtcmVhbG0iLCJhdWQiOlsicmVhbG0tbWFuYWdlbWVudCIsImFjY291bnQiXSwic3ViIjoiYTZkNWE1MzgtNjJjNi00ZGJhLWEyOGEtMmNkMzgwMzgxYzJjIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYmFja2VuZF9jbGllbnRzIiwic2lkIjoiYjNjMGFhYTctNjEzMi00MThlLTg0MTMtNGIxN2M4ZDVjMTY0IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyIiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwiZGVmYXVsdC1yb2xlcy1yZWhlYXJzYWwtcmVhbG0iLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7InJlYWxtLW1hbmFnZW1lbnQiOnsicm9sZXMiOlsidmlldy11c2VycyIsInF1ZXJ5LWdyb3VwcyIsInF1ZXJ5LXVzZXJzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX0sImJhY2tlbmRfY2xpZW50cyI6eyJyb2xlcyI6WyJyZWFkIl19fSwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiUmVhZGVyIFJlYWRlciIsImdyb3VwcyI6WyJyZWFkIl0sInByZWZlcnJlZF91c2VybmFtZSI6InJlYWRlckBwaWEtdGVhbS5jb20iLCJnaXZlbl9uYW1lIjoiUmVhZGVyIiwiZmFtaWx5X25hbWUiOiJSZWFkZXIiLCJlbWFpbCI6InJlYWRlckBwaWEtdGVhbS5jb20ifQ.GAvcZbXW8_9FsZyeM8TmqB0169MJlwCCTO3RLPvD1PnzVIYX5dYfBYdq5adWegN1DoPJ_sTrtKWJLMhhktjf0s3WCkeMzibR6d7Xy5q9bAYuPj5I6CK_nlKoG6RPvCVhwC3dbfFUZ6wnmPicNsTM9sBxGpxeqYo_oxARISqEJBpMmZmX2n2xRNDtpyokId-2g6FUs8Zh7G2um1WbiFttyHbYix8j8_U-Ay0fmVlD9diWFqyCUkV8T7hmRjMVO75gVwclvFAqAW5bqzefw5VsQQv-HFd0eQ70anfwkq5Y24HOi9UcYFMybqJmr0SBNPl7LB2iOhXOCbsVW-zyToJsgA";

  public static final String DIFFERENT_PROVIDER_TOKEN = "eyJ4NXQiOiJaR1F6T0dKaVlXSTRPRFZoTXpsbE16SmxPV1EzWlRaaU9UbG1ZbUprTVRrME5ERTROamhtTXciLCJraWQiOiJaR1F6T0dKaVlXSTRPRFZoTXpsbE16SmxPV1EzWlRaaU9UbG1ZbUprTVRrME5ERTROamhtTXdfUlMyNTYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJTSGFkbTY2NnhAb3V0bG9vay5jb20iLCJhdWQiOiJmTnh1Z3BSMFZuZk44b3hUOGl6RkFQR00yendhIiwibmJmIjoxNjc3ODU4MDkxLCJhenAiOiJmTnh1Z3BSMFZuZk44b3hUOGl6RkFQR00yendhIiwic2NvcGUiOiJvcGVuaWQiLCJvcmdhbml6YXRpb24iOiJWRi1WR0UiLCJpc3MiOiJodHRwczpcL1wvaWRtMS5saXQ0Lm0ybS52b2RhZm9uZS5jb206OTQ0M1wvb2F1dGgyXC90b2tlbiIsImdyb3VwcyI6WyJFTlRFUlBSSVNFLUdVSVwvTTJNUF9PUENPX1NVUFBPUlQiLCJFTlRFUlBSSVNFLUdVSVwvU1BfTTJNUCIsIkVOVEVSUFJJU0UtR1VJXC9TUF9TT0xIVUIiLCJJbnRlcm5hbFwvZXZlcnlvbmUiLCJFTlRFUlBSSVNFLUdVSVwvQURNSU5fQUxMIl0sImV4cCI6MTY3Nzg2MTY5MSwiaWF0IjoxNjc3ODU4MDkxLCJqdGkiOiIyYjI2NjM1Yy01ODQ2LTQ5YmEtYmEyMS01YmNhNTlhNDNkMTAifQ.JQ_vklzWZt56gZ9I3bVgvT6EMXAlbBaI0q3cUoC5IAWIfiqIEnwTUQKlGqtgaZUfiNvSfEiJRfco7Swy2LnTQ7nsEGwYmDP4-4_BiVQFwVUrlTSStmc1ZdOV94w4_6hlTQhvxJZ2-9cstv6PmeOWdswtPXXEpkzadqB_zWEfmckNCFkiAgGJzHkbZ41RONXFX5J7wMPdsz-guRkGyw0XiWU7iHG_Z4a7v7tucNq2RxSwLDCgXVKG-h-YQyyIB8d6jUuqStTu4KtxbEM5M46aBUTblg5kvO97z5_xoFeUasyg-DVhOVn_MjAgVbg_kBRV5HfZAHSO2JpTodi8VpZrCw";

}
