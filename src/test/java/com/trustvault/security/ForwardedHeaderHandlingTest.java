package com.trustvault.security;

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.RemoteIpValve;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.autoconfigure.web.embedded.TomcatWebServerFactoryCustomizer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.core.env.Environment;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Validates forwarded-header processing, trusted reverse-proxy handling,
 * and rate-limiter IP resolution guarantees for Render deployments.
 *
 * <h3>Architectural Context & MockMvc Limitations:</h3>
 * <p>Spring Boot's {@code server.forward-headers-strategy: native} configures Tomcat's
 * {@link RemoteIpValve} on the embedded servlet container pipeline.
 * {@code MockMvc} operates strictly at the {@link org.springframework.web.servlet.DispatcherServlet}
 * layer using {@link MockHttpServletRequest}; it does <i>not</i> boot the underlying Tomcat
 * connector or execute container-level valves. Therefore:
 * <ul>
 *   <li>In {@code MockMvc}, {@code request.getRemoteAddr()} returns whatever the test harness
 *       explicitly sets via {@code with(request -> request.setRemoteAddr(...))}. Setting an
 *       {@code X-Forwarded-For} header in MockMvc does not automatically mutate {@code getRemoteAddr()}
 *       because the Tomcat engine is not involved.</li>
 *   <li>In live production on Render, incoming requests hit Render's router proxy (an internal IP
 *       such as {@code 10.x.x.x}). Tomcat's {@link RemoteIpValve} intercepts the request, verifies
 *       that the incoming socket originates from {@code internalProxies}, extracts the client IP
 *       from {@code X-Forwarded-For}, and calls {@code request.setRemoteAddr(clientIp)}.</li>
 *   <li>Application code (including {@link AuthenticationRateLimitingFilter} and
 *       {@link AuthenticationEventListener}) reads only {@code request.getRemoteAddr()}, never
 *       blindly trusting raw headers directly from untrusted clients.</li>
 * </ul>
 */
@SpringBootTest
class ForwardedHeaderHandlingTest {

    @Autowired
    private ServerProperties serverProperties;

    @Autowired
    private Environment environment;

    @Test
    @DisplayName("1. Actual application configuration binds native forward-headers-strategy and Tomcat remoteip properties")
    void testApplicationServerConfigurationBinding() {
        assertThat(serverProperties.getForwardHeadersStrategy())
                .as("server.forward-headers-strategy must be NATIVE")
                .isEqualTo(ServerProperties.ForwardHeadersStrategy.NATIVE);

        ServerProperties.Tomcat.Remoteip remoteip = serverProperties.getTomcat().getRemoteip();
        assertThat(remoteip.getRemoteIpHeader())
                .as("server.tomcat.remoteip.remote-ip-header must be x-forwarded-for")
                .isEqualTo("x-forwarded-for");
        assertThat(remoteip.getProtocolHeader())
                .as("server.tomcat.remoteip.protocol-header must be x-forwarded-proto")
                .isEqualTo("x-forwarded-proto");
        assertThat(remoteip.getInternalProxies())
                .as("server.tomcat.remoteip.internal-proxies must match the configured trusted internal CIDRs")
                .isEqualTo("10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|169\\.254\\.\\d{1,3}\\.\\d{1,3}|127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[0-1])\\.\\d{1,3}\\.\\d{1,3}|0:0:0:0:0:0:0:1|::1");
    }

    private RemoteIpValve getEffectiveRemoteIpValve() {
        TomcatWebServerFactoryCustomizer customizer = new TomcatWebServerFactoryCustomizer(environment, serverProperties);
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
        customizer.customize(factory);

        return factory.getEngineValves().stream()
                .filter(v -> v instanceof RemoteIpValve)
                .map(v -> (RemoteIpValve) v)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("RemoteIpValve was not registered by TomcatWebServerFactoryCustomizer"));
    }

    @Test
    @DisplayName("2. TomcatWebServerFactoryCustomizer applies configured RemoteIpValve properties to Tomcat engine")
    void testTomcatCustomizerAppliesConfiguredRemoteIpValve() {
        RemoteIpValve configuredValve = getEffectiveRemoteIpValve();

        assertThat(configuredValve)
                .as("Tomcat engine must have RemoteIpValve registered by TomcatWebServerFactoryCustomizer")
                .isNotNull();
        assertThat(configuredValve.getRemoteIpHeader()).isEqualTo("x-forwarded-for");
        assertThat(configuredValve.getProtocolHeader()).isEqualTo("x-forwarded-proto");
        assertThat(configuredValve.getInternalProxies()).isEqualTo(serverProperties.getTomcat().getRemoteip().getInternalProxies());
    }

    @Test
    @DisplayName("3. Configured Tomcat RemoteIpValve extracts genuine client IP from X-Forwarded-For when sent by internal proxy")
    void testRemoteIpValveWithTrustedInternalProxy() throws Exception {
        RemoteIpValve valve = getEffectiveRemoteIpValve();

        // Mock next valve in pipeline to inspect modified request
        final String[] resolvedIpHolder = new String[1];
        valve.setNext(new Valve() {
            private Valve next;
            @Override public Valve getNext() { return next; }
            @Override public void setNext(Valve valve) { this.next = valve; }
            @Override public void backgroundProcess() {}
            @Override public void invoke(Request request, Response response) {
                resolvedIpHolder[0] = request.getRemoteAddr();
            }
            @Override public boolean isAsyncSupported() { return true; }
        });

        Connector connector = new Connector();
        Request request = new Request(connector);
        org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        request.setCoyoteRequest(coyoteRequest);

        // Incoming TCP connection from Render's internal proxy IP
        request.setRemoteAddr("10.0.4.15");
        coyoteRequest.getMimeHeaders().addValue("x-forwarded-for").setString("203.0.113.195");
        coyoteRequest.getMimeHeaders().addValue("x-forwarded-proto").setString("https");

        valve.invoke(request, mock(Response.class));

        // RemoteIpValve must replace 10.0.4.15 with the client IP 203.0.113.195
        assertThat(resolvedIpHolder[0])
                .as("RemoteIpValve must resolve public client IP when request originates from internal proxy")
                .isEqualTo("203.0.113.195");
    }

    @Test
    @DisplayName("4. Configured Tomcat RemoteIpValve discards client-spoofed X-Forwarded-For when proxy appends real IP")
    void testRemoteIpValveDefeatsClientHeaderSpoofing() throws Exception {
        RemoteIpValve valve = getEffectiveRemoteIpValve();

        final String[] resolvedIpHolder = new String[1];
        valve.setNext(new Valve() {
            private Valve next;
            @Override public Valve getNext() { return next; }
            @Override public void setNext(Valve valve) { this.next = valve; }
            @Override public void backgroundProcess() {}
            @Override public void invoke(Request request, Response response) {
                resolvedIpHolder[0] = request.getRemoteAddr();
            }
            @Override public boolean isAsyncSupported() { return true; }
        });

        Connector connector = new Connector();
        Request request = new Request(connector);
        org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        request.setCoyoteRequest(coyoteRequest);

        // Incoming connection from Render internal proxy
        request.setRemoteAddr("10.0.4.15");
        // Attacker spoofed 1.1.1.1, and Render's router appended the real attacker IP 198.51.100.88
        coyoteRequest.getMimeHeaders().addValue("x-forwarded-for").setString("1.1.1.1, 198.51.100.88");

        valve.invoke(request, mock(Response.class));

        // RemoteIpValve inspects from right to left, stopping at the first untrusted IP (198.51.100.88)
        assertThat(resolvedIpHolder[0])
                .as("RemoteIpValve must pick the rightmost untrusted IP (198.51.100.88), defeating spoofed 1.1.1.1")
                .isEqualTo("198.51.100.88");
    }

    @Test
    @DisplayName("5. Configured Tomcat RemoteIpValve ignores X-Forwarded-For if request comes directly from untrusted host")
    void testRemoteIpValveIgnoresHeadersFromUntrustedHosts() throws Exception {
        RemoteIpValve valve = getEffectiveRemoteIpValve();

        final String[] resolvedIpHolder = new String[1];
        valve.setNext(new Valve() {
            private Valve next;
            @Override public Valve getNext() { return next; }
            @Override public void setNext(Valve valve) { this.next = valve; }
            @Override public void backgroundProcess() {}
            @Override public void invoke(Request request, Response response) {
                resolvedIpHolder[0] = request.getRemoteAddr();
            }
            @Override public boolean isAsyncSupported() { return true; }
        });

        Connector connector = new Connector();
        Request request = new Request(connector);
        org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        request.setCoyoteRequest(coyoteRequest);

        // Incoming connection directly from untrusted public IP (not in internalProxies)
        request.setRemoteAddr("198.51.100.22");
        coyoteRequest.getMimeHeaders().addValue("x-forwarded-for").setString("8.8.8.8");

        valve.invoke(request, mock(Response.class));

        // Because remoteAddr is not in internalProxies, X-Forwarded-For is completely ignored
        assertThat(resolvedIpHolder[0])
                .as("X-Forwarded-For must be ignored when request does not come from a trusted internal proxy")
                .isEqualTo("198.51.100.22");
    }

    @Test
    @DisplayName("6. AuthenticationRateLimitingFilter resolves IP strictly via request.getRemoteAddr()")
    void testFilterDoesNotReadRawSpoofedHeadersDirectly() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.10");
        request.addHeader("X-Forwarded-For", "1.1.1.1");
        request.addHeader("X-Real-IP", "2.2.2.2");

        String resolved = AuthenticationRateLimitingFilter.resolveClientIp(request);

        assertThat(resolved)
                .as("Filter must read getRemoteAddr() and never parse raw client-supplied headers directly")
                .isEqualTo("203.0.113.10");
    }

    @Test
    @DisplayName("7. Committed internal-proxies regex matches complete 4-octet IPv4 addresses and rejects incomplete prefixes")
    void testInternalProxiesRegexMatchesCompleteAddresses() {
        String pattern = serverProperties.getTomcat().getRemoteip().getInternalProxies();
        java.util.regex.Pattern regex = java.util.regex.Pattern.compile(pattern);

        // Complete 4-octet IPv4 addresses across all branches
        assertThat(regex.matcher("10.0.4.15").matches()).isTrue();
        assertThat(regex.matcher("192.168.1.1").matches()).isTrue();
        assertThat(regex.matcher("169.254.1.1").matches()).isTrue();
        assertThat(regex.matcher("127.0.0.1").matches()).isTrue();
        assertThat(regex.matcher("172.16.0.1").matches()).isTrue();
        assertThat(regex.matcher("172.31.255.254").matches()).isTrue();
        assertThat(regex.matcher("::1").matches()).isTrue();
        assertThat(regex.matcher("0:0:0:0:0:0:0:1").matches()).isTrue();

        // Incomplete prefixes (must be rejected)
        assertThat(regex.matcher("192.168.1").matches()).isFalse();
        assertThat(regex.matcher("169.254.1").matches()).isFalse();
        assertThat(regex.matcher("10.1.1").matches()).isFalse();
        assertThat(regex.matcher("127.0.0").matches()).isFalse();

        // Out-of-range or public addresses (must be rejected)
        assertThat(regex.matcher("172.32.0.1").matches()).isFalse();
        assertThat(regex.matcher("203.0.113.195").matches()).isFalse();
    }
}
