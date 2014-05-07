package hudson.plugins.collabnet.auth;

import java.rmi.RemoteException;

import com.collabnet.ce.webservices.CollabNetApp;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

public class CollabNetAuthManager implements AuthenticationManager {
    private String collabNetUrl;

    public CollabNetAuthManager(String collabNetUrl) {
        this.collabNetUrl = collabNetUrl;
    }

    public String getCollabNetUrl() {
        return this.collabNetUrl;
    }

    /**
     * @param authentication request object
     * @return fully authenticated object, including credentials
     */
    public Authentication authenticate(Authentication authentication) 
        throws BadCredentialsException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        try {
            CollabNetApp cna = new CollabNetApp(this.getCollabNetUrl(), username, password);
            return new CNAuthentication(authentication.getName(), cna);
        } catch (RemoteException re) {
            throw new BadCredentialsException("Failed to log into " + 
                                              this.getCollabNetUrl() + ": " + 
                                              re.getMessage());
        }
    }
}
