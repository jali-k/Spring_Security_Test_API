package com.jali.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service // To make it a managed bean
/*
* @Component & @Service both can be used to make the class a spring managed bean. But @Service is a specialization of @Component.
* When a class is annotated with @Service, it clearly says that it is a class represents a business service or a layer of business logic.

* jjwt-api, jjwt-impl, jjwt-jackson are the dependencies needed for manipulating a token
*/

/*
A JWT token (Jason Web Token) mainly contain three parts
    1. header
    2. payload
    3. verify signature

   Header:
    Has the tye of the token which is JWT and the algorithm that is used to hash it like HS256

   PLAYLOAD:
    Has the claims. Means the information about the entity, typically the user and extra information like authorities
    There are three types of claims.
        1. Registered claims: a list of predefined claims like [ISS]
        2. Public claims: Claims defined in IANA json web token registry or public by nature
        3. Private claims: Custom claims created to share information among parties that agree using them

    VERIFY SIGNATURE:
        To verify the sender of the JWT is who it is claims to be and to ensure that the message wasn't changed along the way

 */
public class Jwtservice {
    private static final String SECRET_kEY = "244226452948404D635166546A576E5A7234753778214125432A462D4A614E64"; // This is public bcz I'm not using it in any of my APIs
    public String extractUsername(String token) {

        return extractClaim(token, Claims::getSubject); // The subject is the username related to the token
    /*
    :: Operator:
        :: Operator is known as method reference operator introduced in Java 8. To refer to methods or constructors by their names.
        It is used to pass a reference to a method or a constructor as a functional interface or a lambda expression.

        In that above code, Claims::getSubject is a method reference that refers to the getSubject method of the Claims class.
        It matches with the input output s that is expected in the extractClaim method.
     */
    }

    // Before extracting the username, we need a method to extract all the claims.

    /*
    Signing Key:
        Signing key is the secret that is used to digitally sign in the JWt. It is used to create the signature part of the JWT
        which is used to verify the sender is who it is claimed to be and ensure that the message was not changed along the way.
        We need to ensure the person that gets a JWT key is the one who is gonna claim .me
        Signing key is working with signing algorithm in JWT header to create the signature. This signing algorithm and key size
        depends on the security level you need. Also also with the trust of the signing party.
     */

    // We are having a method to extract all the claims below. Then we need an another method to extract a  single claim that we pass also.
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        /*
        <T> T:
        Generic type <T>
          These can work with different types
          The <T> indicates that the method is generic and can work with any type specified during its invocation.
          The T type is used as the return type of the function.
         */
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // What if we need to generate only with user details
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }


    // Lets create a method to generate the token that uses the username and claims
    public String generateToken(
            Map<String, Object> extractClaims, // This will contain the extracted claims that we need to add like add authorities
            UserDetails userDetails // User details

    ){
        return Jwts
                .builder()
                .setClaims(extractClaims) // Set our claims
                .setSubject(userDetails.getUsername()) // The subject is the userEmail
                .setIssuedAt(new Date(System.currentTimeMillis())) // When the token is created
                .setExpiration(new Date(System.currentTimeMillis() * 1000 * 24)) // How long does the token valid
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // Which key that you need to sign this token
                .compact(); // The method that will generate and return the token
    }


    // This is the method to validate a token
    public boolean isTakenValid(String token, UserDetails userDetails){ // Why we need user details here is, we need to check whether the given token is relevant to the user.
    final String userName = extractUsername(token); // Take the userName (email actually)
    return (userName.equals(userDetails.getUsername())) && !isTakenExpired(token);
    }

    // Check weather the taken is expired
    private boolean isTakenExpired(String token) {
    return extractExpiration(token).before(new Date()); // Check weather the expiration date is before today
    }

    // Extracting the expiration date of the token
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // A method to extract all the claims

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey()) // To pass the signing key
                .build() // Bcz this is a builder
                .parseClaimsJws(token) // Pass the claims. This verify the signature
                .getBody(); // Get the token body
    }

    //Getting the signing key according to the secret key
    private Key getSignInKey() {

        byte[] keyBytes = Decoders.BASE64.decode(SECRET_kEY);
        return Keys.hmacShaKeyFor(keyBytes); // hmacShaKeyFor is that algo to generate the signing key
    }
}
