/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jasig.cas.client.jaas;

import static org.junit.Assert.*;
import java.security.Principal;
import java.security.acl.Group;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import org.jasig.cas.client.PublicTestHttpServer;
import org.jasig.cas.client.validation.TicketValidationException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit test for {@link CasLoginModule} class.
 *
 * @author Marvin S. Addison
 * @version $Revision$
 *
 */
public class CasLoginModuleTests {

    private static final PublicTestHttpServer server = PublicTestHttpServer.instance(8091);

    private static final String CONST_CAS_SERVER_URL = "http://localhost:8091/";

    private Map<String, String> options;

    /* @AfterClass
     public static void classCleanUp() {
         server.shutdown();
     }*/

    @Before
    public void setUp() throws Exception {
        options = new HashMap<String, String>();
        options.put("ticketValidatorClass", "org.jasig.cas.client.validation.Cas20ServiceTicketValidator");
        options.put("casServerUrlPrefix", CONST_CAS_SERVER_URL);
        options.put("proxyCallbackUrl", "https://service.example.com/webapp/proxy");
        options.put("renew", "true");
        options.put("defaultRoles", "ADMIN");
        options.put("principalGroupName", "CallerPrincipal");
        options.put("roleGroupName", "Roles");
    }

    /**
     * Test JAAS login success.
     * @throws Exception On errors.
     */
    @Test
    public void testLoginSuccess() throws Exception {
        final String USERNAME = "username";
        final String SERVICE = "https://example.com/service";
        final String TICKET = "ST-100000-aA5Yuvrxzpv8Tau1cYQ7-srv1";
        final String RESPONSE = "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>"
                + "<cas:authenticationSuccess><cas:user>" + USERNAME
                + "</cas:user></cas:authenticationSuccess></cas:serviceResponse>";
        server.content = RESPONSE.getBytes(server.encoding);

        final CasLoginModule module = new CasLoginModule();
        final Subject subject = new Subject();
        module.initialize(
                subject,
                new ServiceAndTicketCallbackHandler(SERVICE, TICKET),
                new HashMap<String, Object>(),
                options);
        module.login();
        module.commit();
        assertEquals(subject.getPrincipals().size(), 3);
        assertEquals(TICKET, subject.getPrivateCredentials().iterator().next().toString());
        assertTrue(hasPrincipalName(subject, Group.class, "CallerPrincipal"));
        assertTrue(hasPrincipalName(subject, Group.class, "Roles"));
        final AssertionPrincipal principal = getPrincipal(subject, AssertionPrincipal.class);
        assertEquals(USERNAME, principal.getName());
        final Matcher m = CasLoginModule.UNIQUE_SUFFIX_PATTERN.matcher(principal.getServicePrincipal());
        assertTrue(m.matches());
    }


    /**
     * Test JAAS login success.
     * @throws Exception On errors.
     */
    @Test
    public void testLoginSuccessUniquePrincipal() throws Exception {
        final String USERNAME = "alice";
        final String SERVICE = "https://example.com/service" + CasLoginModule.createUniqueSuffix();
        final String TICKET = "ST-100001-aA5Zabcxzpv8Tau1abeZ-srv1";
        final String RESPONSE = "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>"
                + "<cas:authenticationSuccess><cas:user>" + USERNAME
                + "</cas:user></cas:authenticationSuccess></cas:serviceResponse>";
        server.content = RESPONSE.getBytes(server.encoding);

        final CasLoginModule module = new CasLoginModule();
        final Subject subject = new Subject();
        module.initialize(
                subject,
                new ServiceAndTicketCallbackHandler(SERVICE, TICKET),
                new HashMap<String, Object>(),
                options);
        module.login();
        module.commit();
        assertEquals(subject.getPrincipals().size(), 3);
        assertEquals(TICKET, subject.getPrivateCredentials().iterator().next().toString());
        assertTrue(hasPrincipalName(subject, Group.class, "CallerPrincipal"));
        assertTrue(hasPrincipalName(subject, Group.class, "Roles"));
        final AssertionPrincipal principal = getPrincipal(subject, AssertionPrincipal.class);
        assertEquals(USERNAME, principal.getName());
        assertEquals(SERVICE, principal.getServicePrincipal());
    }

    /**
     * Test JAAS login failure.
     * @throws Exception On errors.
     */
    @Test
    public void testLoginFailure() throws Exception {
        final String SERVICE = "https://example.com/service";
        final String TICKET = "ST-200000-aA5Yuvrxzpv8Tau1cYQ7-srv1";
        final String RESPONSE = "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'><cas:authenticationFailure code=\"INVALID_TICKET\">Ticket ST-200000-aA5Yuvrxzpv8Tau1cYQ7-srv1 not recognized</cas:authenticationFailure></cas:serviceResponse>";
        server.content = RESPONSE.getBytes(server.encoding);

        final CasLoginModule module = new CasLoginModule();
        final Subject subject = new Subject();
        module.initialize(
                subject,
                new ServiceAndTicketCallbackHandler(SERVICE, TICKET),
                new HashMap<String, Object>(),
                options);
        try {
            module.login();
            fail("Login did not throw FailedLoginException as expected.");
        } catch (LoginException e) {
            assertEquals(TicketValidationException.class, e.getCause().getClass());
        }
        module.commit();
        assertNull(module.ticket);
        assertNull(module.assertion);
    }

    /**
     * Test JAAS logout after successful login to ensure subject cleanup.
     * @throws Exception On errors.
     */
    @Test
    public void testLogout() throws Exception {
        final String USERNAME = "username";
        final String SERVICE = "https://example.com/service";
        final String TICKET = "ST-100000-aA5Yuvrxzpv8Tau1cYQ7-srv1";
        final String RESPONSE = "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>"
                + "<cas:authenticationSuccess><cas:user>" + USERNAME
                + "</cas:user></cas:authenticationSuccess></cas:serviceResponse>";
        server.content = RESPONSE.getBytes(server.encoding);

        final CasLoginModule module = new CasLoginModule();
        final Subject subject = new Subject();
        module.initialize(
                subject,
                new ServiceAndTicketCallbackHandler(SERVICE, TICKET),
                new HashMap<String, Object>(),
                options);
        module.login();
        module.commit();
        assertEquals(subject.getPrincipals().size(), 3);
        assertEquals(TICKET, subject.getPrivateCredentials().iterator().next().toString());
        assertTrue(hasPrincipalName(subject, Group.class, "CallerPrincipal"));
        assertTrue(hasPrincipalName(subject, Group.class, "Roles"));
        final AssertionPrincipal principal = getPrincipal(subject, AssertionPrincipal.class);
        assertEquals(USERNAME, principal.getName());
        final Matcher m = CasLoginModule.UNIQUE_SUFFIX_PATTERN.matcher(principal.getServicePrincipal());
        assertTrue(m.matches());

        module.logout();
        assertEquals(0, subject.getPrincipals().size());
        assertEquals(0, subject.getPrivateCredentials().size());
    }

    /**
     * Confirm that CasLoginModule#logout() destroys cached data and prevents subsequent login w/expired ticket.
     * @throws Exception On errors.
     */
    @Test
    public void testAssertionCaching() throws Exception {
        final String USERNAME = "username";
        final String SERVICE = "https://example.com/service";
        final String TICKET = "ST-300000-aA5Yuvrxzpv8Tau1cYQ7-srv1";
        final String SUCCESS_RESPONSE = "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>"
                + "<cas:authenticationSuccess><cas:user>" + USERNAME
                + "</cas:user></cas:authenticationSuccess></cas:serviceResponse>";
        final String FAILURE_RESPONSE = "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'><cas:authenticationFailure code=\"INVALID_TICKET\">Ticket ST-300000-aA5Yuvrxzpv8Tau1cYQ7-srv1 not recognized</cas:authenticationFailure></cas:serviceResponse>";

        options.put("cacheAssertions", "true");
        options.put("cacheTimeout", "1");

        server.content = SUCCESS_RESPONSE.getBytes(server.encoding);

        final CasLoginModule module = new CasLoginModule();
        final Subject subject = new Subject();
        module.initialize(
                subject,
                new ServiceAndTicketCallbackHandler(SERVICE, TICKET),
                new HashMap<String, Object>(),
                options);
        module.login();
        module.commit();
        assertEquals(subject.getPrincipals().size(), 3);
        assertEquals(TICKET, subject.getPrivateCredentials().iterator().next().toString());

        // Logout should destroy all authenticated state data including assertion cache entries
        module.logout();
        assertEquals(0, subject.getPrincipals().size());
        assertEquals(0, subject.getPrivateCredentials().size());
        server.content = FAILURE_RESPONSE.getBytes(server.encoding);

        // Verify we can't log in again with same ticket
        module.initialize(
                subject,
                new ServiceAndTicketCallbackHandler(SERVICE, TICKET),
                new HashMap<String, Object>(),
                options);
        try {
            module.login();
            module.commit();
            Assert.fail("Login should have failed.");
        } catch (LoginException e) {
            assertEquals(TicketValidationException.class, e.getCause().getClass());
        }
        assertEquals(0, subject.getPrincipals().size());
        assertEquals(0, subject.getPrivateCredentials().size());
    }

    /**
     * Verify that cached assertions that are expired are never be accessible
     * by {@link org.jasig.cas.client.jaas.CasLoginModule#login()} method.
     *
     * @throws Exception On errors.
     */
    @Test
    public void testAssertionCachingExpiration() throws Exception {
        final String USERNAME = "hizzy";
        final String SERVICE = "https://example.com/service";
        final String TICKET = "ST-12345-ABCDEFGHIJKLMNOPQRSTUVWXYZ-hosta";
        final String SUCCESS_RESPONSE = "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>"
                + "<cas:authenticationSuccess><cas:user>" + USERNAME
                + "</cas:user></cas:authenticationSuccess></cas:serviceResponse>";
        final String FAILURE_RESPONSE = "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'><cas:authenticationFailure code=\"INVALID_TICKET\">Ticket ST-12345-ABCDEFGHIJKLMNOPQRSTUVWXYZ-hosta not recognized</cas:authenticationFailure></cas:serviceResponse>";

        options.put("cacheAssertions", "true");
        // Cache timeout is 1 second
        options.put("cacheTimeoutUnit", "SECONDS");
        options.put("cacheTimeout", "1");

        server.content = SUCCESS_RESPONSE.getBytes(server.encoding);

        final CasLoginModule module = new CasLoginModule();
        final Subject subject = new Subject();
        module.initialize(
                subject,
                new ServiceAndTicketCallbackHandler(SERVICE, TICKET),
                new HashMap<String, Object>(),
                options);
        assertTrue(module.login());
        module.commit();

        Thread.sleep(1100);
        // Assertion should now be expired from cache
        server.content = FAILURE_RESPONSE.getBytes(server.encoding);
        module.initialize(
                subject,
                new ServiceAndTicketCallbackHandler(SERVICE, TICKET),
                new HashMap<String, Object>(),
                options);
        try {
            module.login();
            fail("Should have thrown FailedLoginException.");
        } catch (LoginException e) {
            assertEquals(TicketValidationException.class, e.getCause().getClass());
        }
    }

    private <T extends Principal> T getPrincipal(final Subject subject, final Class<T> principalType)
    {
        return subject.getPrincipals(principalType).iterator().next();
    }

    private boolean hasPrincipalName(final Subject subject, final Class<? extends Principal> principalClass,
            final String name) {
        final Set<? extends Principal> principals = subject.getPrincipals(principalClass);
        for (Principal p : principals) {
            if (p.getName().equals(name)) {
                return true;
            }
        }
        return false;
    }
}
