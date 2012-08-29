package hudson.plugins.collabnet.auth;

import com.collabnet.ce.webservices.CollabNetApp;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.plugins.collabnet.util.CNHudsonUtil;
import hudson.security.AccessDeniedHandlerImpl;
import hudson.security.SecurityRealm;
import hudson.security.UnwrapSecurityExceptionFilter;
import hudson.util.FormValidation;
import hudson.util.VersionNumber;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.Filter;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.springframework.security.providers.anonymous.AnonymousProcessingFilter;
import org.springframework.security.ui.ExceptionTranslationFilter;
import org.springframework.security.userdetails.memory.UserAttribute;


public class CollabNetSecurityRealm extends SecurityRealm {
    private String collabNetUrl;

    /* viewing Jenkins page from CTF linked app should login to Jenkins */
    private boolean mEnableSSOAuthFromCTF;

    /* logging in to Jenkins should login to CTF */
    private boolean mEnableSSOAuthToCTF;

    private boolean mEnableSSORedirect = true;

    @DataBoundConstructor
    public CollabNetSecurityRealm(String collabNetUrl, boolean enableSSOAuthFromCTF, boolean enableSSOAuthToCTF) {
        this.collabNetUrl = CNHudsonUtil.sanitizeCollabNetUrl(collabNetUrl);
        this.mEnableSSOAuthFromCTF = enableSSOAuthFromCTF;
        this.mEnableSSOAuthToCTF = enableSSOAuthToCTF;

        CollabNetApp cn = new CollabNetApp(this.collabNetUrl);
        try {
            VersionNumber apiVersion = new VersionNumber(cn.getApiVersion());
            if (apiVersion.compareTo(new VersionNumber("5.3.0.0")) >= 0) {
                // starting with CTF 5.3, redirect no longer works after login
                mEnableSSORedirect = false;
            }
        } catch (RemoteException re) {
            // ignore
            LOGGER.log(Level.WARNING, "Failed to retrieve the CTF version from "+this.collabNetUrl,re);
        }
    }

    public String getCollabNetUrl() {
        return this.collabNetUrl;
    }

    /**
     * Single sign on preference governing making Jenkins read CTF's SSO token
     * @return true to enable
     */
    public boolean getEnableSSOAuthFromCTF() {
        return mEnableSSOAuthFromCTF;
    }

    /**
     * Single sign on preference governing making Jenkins login to CTF upon authenticating
     * @return true to enable
     */
    public boolean getEnableSSOAuthToCTF() {
        return mEnableSSOAuthToCTF;
    }

    /**
     * Whether after singole singon into CTF, we should automatically redirect back to Jenkins.
     * @return true to enable
     */
    public boolean getEnableSSORedirect() {
        return mEnableSSORedirect;
    }

    @Override
    public SecurityRealm.SecurityComponents createSecurityComponents() {
        return new SecurityRealm.SecurityComponents(new CollabNetAuthManager
                                                    (this.getCollabNetUrl()));
    }

    /**
     * Override the default getCommonFilters.  We want to use one that does not
     * return a 403 on login redirect because that may cause problems when
     * Jenkins is run behind a proxy.
     */
    @Override
    public Filter[] getCommonFilters() {
        AnonymousProcessingFilter anonymousProcessingFilter = new AnonymousProcessingFilter();
        anonymousProcessingFilter.setKey("anonymous"); // must match with the AnonymousProvider
        UserAttribute userAttribute = new UserAttribute();
        userAttribute.setPassword("anonymous");
        String authorities = "anonymous, ROLE_ANONYMOUS";
        userAttribute.setAuthoritiesAsString(Arrays.asList(authorities));
        anonymousProcessingFilter.setUserAttribute(userAttribute);

        ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter();
        AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
        exceptionTranslationFilter.setAccessDeniedHandler(accessDeniedHandler);
        
        CNAuthenticationEntryPoint cnAuthenticationEntryPoint = new CNAuthenticationEntryPoint();
        cnAuthenticationEntryPoint.setLoginFormUrl('/' + getLoginUrl() + "?from={0}");
        exceptionTranslationFilter.setAuthenticationEntryPoint(cnAuthenticationEntryPoint);


        UnwrapSecurityExceptionFilter unwrapSecurityExceptionFilter = new UnwrapSecurityExceptionFilter();

        Filter[] filters = {
            anonymousProcessingFilter,
            exceptionTranslationFilter,
            unwrapSecurityExceptionFilter
        };

        return filters;
    }

    /**
     * The CollabNetSecurityRealm Descriptor class.
     */
    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        /**
         * @return string to display for configuration screen.
         */
        @Override
        public String getDisplayName() {
            return "CollabNet Security Realm";
        }

        /**
         * Form validation for the CollabNet URL.
         *
         * @param value url
         */
        public FormValidation doCheckCollabNetUrl(@QueryParameter String value) {
            if (!Hudson.getInstance().hasPermission(Hudson.ADMINISTER)) {
                return FormValidation.ok();
            }
            String collabNetUrl = value;
            if (collabNetUrl == null || collabNetUrl.equals("")) {
                return FormValidation.error("The CollabNet URL is required.");
            }
            if (!checkSoapUrl(collabNetUrl)) {
                return FormValidation.error("Invalid CollabNet URL.");
            }
            return FormValidation.ok();
        }
        
        /**
         * Check that a URL has the expected SOAP service.
         *
         * @param collabNetUrl for the CollabNet server
         * @return returns true if we can get a wsdl from the url, which
         *         indicates that it's a working CollabNet server.
         */
        private boolean checkSoapUrl(String collabNetUrl) {
            String soapURL = collabNetUrl + CollabNetApp.SOAP_SERVICE + 
                "CollabNet?wsdl";
            HttpClient client = new HttpClient();
            try {
                GetMethod get = new GetMethod(soapURL);
                int status = client.executeMethod(get);
                return status == 200;
            } catch (IOException e) {
                return false;
            } catch (IllegalArgumentException iae) {
                return false;
            }
        }    
    }

    private static final Logger LOGGER = Logger.getLogger(CollabNetSecurityRealm.class.getName());
}
