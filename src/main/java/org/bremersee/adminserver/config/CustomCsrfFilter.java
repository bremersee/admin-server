/*
 * Copyright 2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bremersee.adminserver.config;

import static org.springframework.util.ObjectUtils.isEmpty;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.jspecify.annotations.NonNull;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

/**
 * The custom csrf filter is required to make CSRF token available to JavaScript.
 *
 * @author docs.spring-boot-admin.com
 */
class CustomCsrfFilter extends OncePerRequestFilter {

  /**
   * The constant CSRF_COOKIE_NAME.
   */
  public static final String CSRF_COOKIE_NAME = "XSRF-TOKEN";

  /**
   * Instantiates a new custom csrf filter.
   */
  CustomCsrfFilter() {
    super();
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain) throws ServletException, IOException {

    CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

    if (csrf != null) {
      Cookie cookie = WebUtils.getCookie(request, CSRF_COOKIE_NAME);
      String token = isEmpty(csrf.getToken()) ? null : csrf.getToken();

      if (cookie == null || token != null && !token.equals(cookie.getValue())) {
        cookie = new Cookie(CSRF_COOKIE_NAME, token);
        cookie.setPath("/");
        response.addCookie(cookie);
      }
    }

    filterChain.doFilter(request, response);
  }

}
