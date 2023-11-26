package com.securebank.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CsrfCookieFilter extends OncePerRequestFilter {

    /**
     * Extends OncePerRequestFilter: Indicates that this filter should only execute once per request.
     *
     *** doFilterInternal method: This method is where the actual filtering logic takes place. It overrides the method from the superclass (OncePerRequestFilter).
     * The main purpose is to extract the CSRF token from the request attributes and set it as a header in the response.
     *
     *** CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());: Retrieves the CSRF token from the request attributes. This assumes that a CSRF token has been set as an attribute in a previous step of the request processing.
     *
     *** if (null != csrfToken.getHeaderName()) { response.setHeader(csrfToken.getHeaderName(), csrfToken.getToken()); }: Checks if the CSRF token has a header name (some implementations might not have one) and sets this token as a header in the HTTP response. This is important for clients (e.g., browsers) to be able to read and include the CSRF token in subsequent requests.
     *
     *** filterChain.doFilter(request, response);: Invokes the next filter in the chain. This line ensures that the request continues to be processed by other filters and eventually reaches the servlet or endpoint.
     *
     */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (null != csrfToken.getHeaderName()) {
            response.setHeader(csrfToken.getHeaderName(), csrfToken.getToken());
        }
        filterChain.doFilter(request, response);
    }
}
