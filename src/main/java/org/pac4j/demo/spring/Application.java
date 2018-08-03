package org.pac4j.demo.spring;

import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.Pac4jConstants;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.http.client.indirect.FormClient;
import org.pac4j.jwt.config.encryption.SecretEncryptionConfiguration;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.profile.JwtGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Controller
public class Application {

    private static final String PROFILES = "profiles";
    private static final String SESSION_ID = "sessionId";

    @Value("${salt}")
    private String salt;

    @Autowired
    private Config config;

    @RequestMapping("/")
    public String root(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) throws HttpAction {
        return index(request, response, map);
    }

    @RequestMapping("/index.html")
    public String index(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) throws HttpAction {
        final WebContext context = new J2EContext(request, response);
        map.put(PROFILES, getProfiles(context));
        map.put(SESSION_ID, context.getSessionStore().getOrCreateSessionId(context));
        return "index";
    }

    private List<CommonProfile> getProfiles(final WebContext context) {
        final ProfileManager manager = new ProfileManager(context);
        return manager.getAll(true);
    }

    @RequestMapping("/facebook/index.html")
    public String facebook(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/facebook/notprotected.html")
    public String facebookNotProtected(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        final WebContext context = new J2EContext(request, response);
        map.put(PROFILES, getProfiles(context));
        return "notProtected";
    }

    @RequestMapping("/facebookadmin/index.html")
    public String facebookadmin(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/facebookcustom/index.html")
    public String facebookcustom(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/twitter/index.html")
    public String twitter(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/form/index.html")
    public String form(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/basicauth/index.html")
    public String basicauth(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/cas/index.html")
    public String cas(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/casrest/index.html")
    public String casrest(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/saml/index.html")
    public String saml(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        final WebContext context = new J2EContext(request, response);
        map.put(PROFILES, getProfiles(context));
        return "samlIndex";
    }

    @RequestMapping("/saml/admin.html")
    public String samlAdmin(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        final WebContext context = new J2EContext(request, response);
        map.put(PROFILES, getProfiles(context));
        return "samlAdmin";
    }

    @RequestMapping("/oidc/index.html")
    public String oidc(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/protected/index.html")
    public String protect(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/dba/index.html")
    public String dba(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/rest-jwt/index.html")
    public String restJwt(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/jwt.html")
    public String jwt(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        final JwtGenerator generator = new JwtGenerator(new SecretSignatureConfiguration(salt), new SecretEncryptionConfiguration(salt));
        final WebContext context = new J2EContext(request, response);
        String token = "";
        final ProfileManager manager = new ProfileManager(context);
        final Optional<CommonProfile> profile = manager.get(true);
        if (profile.isPresent()) {
            token = generator.generate(profile.get());
        }
        map.put("token", token);
        return "jwt";
    }

    @RequestMapping("/loginForm")
    public String loginForm(Map<String, Object> map) {
        final FormClient formClient = (FormClient) config.getClients().findClient("FormClient");
        map.put("callbackUrl", formClient.getCallbackUrl());
        return "form";
    }

    @RequestMapping("/forceLogin")
    public String forceLogin(HttpServletRequest request, HttpServletResponse response) {

        final J2EContext context = new J2EContext(request, response);
        final Client client = config.getClients().findClient(request.getParameter(Pac4jConstants.DEFAULT_CLIENT_NAME_PARAMETER));
        try {
            client.redirect(context);
        } catch (final HttpAction e) {
        }
        return null;
    }

    protected String protectedIndex(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        final WebContext context = new J2EContext(request, response);
        map.put(PROFILES, getProfiles(context));
        return "protectedIndex";
    }
}
