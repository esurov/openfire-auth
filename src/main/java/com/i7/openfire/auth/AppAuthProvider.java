package com.i7.openfire.auth;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import org.jivesoftware.openfire.auth.AuthProvider;
import org.jivesoftware.openfire.auth.ConnectionException;
import org.jivesoftware.openfire.auth.InternalUnauthenticatedException;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.i7.openfire.config.Properties;

import io.jsonwebtoken.Jwts;

public class AppAuthProvider implements AuthProvider {
    private static final Logger log = LoggerFactory.getLogger(AppAuthProvider.class);

    public AppAuthProvider(){
        log.debug("Creating AppAuthProvider");
    }

    @Override
    public void authenticate(final String user, final String password) throws UnauthorizedException, ConnectionException, InternalUnauthenticatedException {
        log.debug("authenticating user {} with password {}", user, password);
        
        Properties properties = Properties.getInstance();
        PublicKey key = getPublicKey(properties.getKeyPath());
        
		try {
			//assert Jwts.parser().setSigningKey(key).parseClaimsJws(password).getHeader().get("authenticated").equals(true);
			String issuer = Jwts.parser().setSigningKey(key).parseClaimsJws(password).getBody().getIssuer();
			String subject = Jwts.parser().setSigningKey(key).parseClaimsJws(password).getBody().getSubject();
			Date expiration = Jwts.parser().setSigningKey(key).parseClaimsJws(password).getBody().getExpiration();
			
			assert !Strings.isNullOrEmpty(issuer) && !Strings.isNullOrEmpty(subject) && expiration != null;
			assert issuer.equals(properties.getIssuer()) && subject.equals(user) && expiration.after(new Date());
		} catch (AssertionError e) {
			log.warn("user {} authentication failed: {}", user, e.getMessage());
			throw new UnauthorizedException("Username " + user + " not allowed to login!: " + e.getMessage());
		}
		log.debug("user {} authenticated succesfully", user);
    }

    @Override
    public String getPassword(String s) throws UserNotFoundException, UnsupportedOperationException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setPassword(String s, String s1) throws UserNotFoundException, UnsupportedOperationException {
        throw new UnsupportedOperationException();
    }

	@Override
    public String getSalt(String username) throws UnsupportedOperationException, UserNotFoundException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getIterations(String username) throws UnsupportedOperationException, UserNotFoundException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getServerKey(String username) throws UnsupportedOperationException, UserNotFoundException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getStoredKey(String username) throws UnsupportedOperationException, UserNotFoundException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean supportsPasswordRetrieval() {
        return false;
    }

    @Override
    public boolean isScramSupported() {
        return false;
    }

    public boolean isPlainSupported() {
        return true;
    }

    public boolean isDigestSupported() {
        return false;
    }

    public void authenticate(String username, String token, String digest) throws UnauthorizedException, ConnectionException, InternalUnauthenticatedException {
        log.debug("authenticating user {} with token {} and digest {}", new Object[]{username, token, digest});
        throw new UnsupportedOperationException("auth with digest not supported!");
    }

    private PublicKey getPublicKey(String uri) {
        log.debug("Retrieving key from path: " +  uri);

        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(uri));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            log.error("Private key retrieval failed: ", e.getMessage());
            throw new InternalError();
        }
    }
}
