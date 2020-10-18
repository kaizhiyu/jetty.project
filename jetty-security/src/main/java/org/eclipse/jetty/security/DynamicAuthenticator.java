package org.eclipse.jetty.security;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.pathmap.MappedResource;
import org.eclipse.jetty.http.pathmap.PathMappings;
import org.eclipse.jetty.http.pathmap.PathSpec;
import org.eclipse.jetty.http.pathmap.ServletPathSpec;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.security.Constraint;

public class DynamicAuthenticator implements Authenticator
{
    private final PathMappings<AuthenticatorEntry> _mappings = new PathMappings<>();

    private Authenticator getAuthenticator(ServletRequest request)
    {
        HttpServletRequest httpRequest = (HttpServletRequest)request;
        String pathInfo = httpRequest.getPathInfo();
        MappedResource<AuthenticatorEntry> match = _mappings.getMatch(pathInfo == null ? "" : pathInfo);
        if (match == null)
            return null;

        return match.getResource().getAuthenticator();
    }

    public void addMapping(String pathSpec, AuthenticatorEntry entry)
    {
        addMapping(new ServletPathSpec(pathSpec), entry);
    }

    public void addMapping(PathSpec pathSpec, AuthenticatorEntry entry)
    {
        _mappings.put(pathSpec, entry);
    }

    @Override
    public void setConfiguration(AuthConfiguration configuration)
    {
        for (MappedResource<AuthenticatorEntry> mapping : _mappings)
        {
            AuthenticatorEntry entry = mapping.getResource();
            DynamicConfiguration config = new DynamicConfiguration(configuration, entry);
            entry.getAuthenticator().setConfiguration(config);
        }
    }

    @Override
    public String getAuthMethod()
    {
        return Constraint.__DYNAMIC_AUTH;
    }

    @Override
    public void prepareRequest(ServletRequest request)
    {
        Authenticator authenticator = getAuthenticator(request);
        if (authenticator == null)
            return;

        authenticator.prepareRequest(request);
    }

    @Override
    public Authentication validateRequest(ServletRequest request, ServletResponse response, boolean mandatory) throws ServerAuthException
    {
        final Request baseRequest = Objects.requireNonNull(Request.getBaseRequest(request));
        final Response baseResponse = baseRequest.getResponse();

        Authenticator authenticator = getAuthenticator(request);
        if (authenticator == null)
        {
            try
            {
                baseResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
                return Authentication.SEND_FAILURE;
            }
            catch (IOException e)
            {
                throw new ServerAuthException(e);
            }
        }

        return authenticator.validateRequest(request, response, mandatory);
    }

    @Override
    public boolean secureResponse(ServletRequest request, ServletResponse response, boolean mandatory, Authentication.User validatedUser) throws ServerAuthException
    {
        Authenticator authenticator = getAuthenticator(request);
        if (authenticator == null)
            return true;

        return authenticator.secureResponse(request, response, mandatory, validatedUser);
    }

    public static class AuthenticatorEntry
    {
        private final Authenticator authenticator;
        private final LoginService loginService;
        private final IdentityService identityService;

        public AuthenticatorEntry(Authenticator authenticator)
        {
            this(authenticator, null, null);
        }

        public AuthenticatorEntry(Authenticator authenticator, LoginService loginService)
        {
            this(authenticator, loginService, null);
        }

        public AuthenticatorEntry(Authenticator authenticator, LoginService loginService, IdentityService identityService)
        {
            this.authenticator = Objects.requireNonNull(authenticator);
            this.loginService = loginService;
            this.identityService = identityService;
        }

        public Authenticator getAuthenticator()
        {
            return authenticator;
        }

        public LoginService getLoginService()
        {
            return loginService;
        }

        public IdentityService getIdentityService()
        {
            return identityService;
        }

        @Override
        public String toString()
        {
            return String.format("%s{%s,%s,%s}", getClass().getSimpleName(), authenticator, loginService, identityService);
        }
    }

    private static class DynamicConfiguration implements AuthConfiguration
    {
        private final AuthConfiguration configuration;
        private final LoginService loginService;
        private final IdentityService identityService;

        public DynamicConfiguration(AuthConfiguration configuration, AuthenticatorEntry entry)
        {
            this.configuration = configuration;
            this.loginService = entry.getLoginService() == null ? configuration.getLoginService() : entry.getLoginService();
            this.identityService = entry.getIdentityService() == null ? configuration.getIdentityService() : entry.getIdentityService();
        }

        @Override
        public String getAuthMethod()
        {
            return configuration.getAuthMethod();
        }

        @Override
        public String getRealmName()
        {
            return configuration.getRealmName();
        }

        @Override
        public String getInitParameter(String param)
        {
            return configuration.getInitParameter(param);
        }

        @Override
        public Set<String> getInitParameterNames()
        {
            return configuration.getInitParameterNames();
        }

        @Override
        public LoginService getLoginService()
        {
            return loginService;
        }

        @Override
        public IdentityService getIdentityService()
        {
            return identityService;
        }

        @Override
        public boolean isSessionRenewedOnAuthentication()
        {
            return configuration.isSessionRenewedOnAuthentication();
        }
    }
}
