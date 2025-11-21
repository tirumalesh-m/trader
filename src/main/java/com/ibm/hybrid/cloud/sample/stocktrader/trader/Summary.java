/*
       Copyright 2017-2021 IBM Corp All Rights Reserved
       Copyright 2022-2025 Kyndryl, All Rights Reserved

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package com.ibm.hybrid.cloud.sample.stocktrader.trader;

import com.ibm.hybrid.cloud.sample.stocktrader.trader.client.BrokerClient;
import com.ibm.hybrid.cloud.sample.stocktrader.trader.json.Broker;

import java.io.IOException;

//JSR 47 Logging
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

//CDI 2.0
import io.opentelemetry.instrumentation.annotations.WithSpan;
import jakarta.inject.Inject;
import jakarta.enterprise.context.ApplicationScoped;

//Servlet 4.0
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.HttpConstraint;
import jakarta.servlet.annotation.ServletSecurity;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.RequestDispatcher;

//mpConfig 1.3
import org.eclipse.microprofile.config.inject.ConfigProperty;

//mpJWT 1.0
import org.eclipse.microprofile.jwt.JsonWebToken;

//mpRestClient 1.0
import org.eclipse.microprofile.rest.client.inject.RestClient;

import org.apache.commons.math3.stat.descriptive.SynchronizedDescriptiveStatistics;

/**
 * Servlet implementation class Summary
 */
@WebServlet(description = "Broker summary servlet", urlPatterns = { "/summary" })
@ServletSecurity(@HttpConstraint(rolesAllowed = { "StockTrader", "StockViewer" } ))
@ApplicationScoped
public class Summary extends HttpServlet {
	private static final long serialVersionUID = 4815162342L;
	private static final String LOGOUT   = "Log Out";
	private static final String PREVIOUS   = "Previous";
	private static final String NEXT   = "Next";
	private static final String CREATE   = "create";
	private static final String RETRIEVE = "retrieve";
	private static final String UPDATE   = "update";
	private static final String DELETE   = "delete";
	private static final String POST     = "post";
	private static final String TOKEN    = "access_token";
	private static final String JWT      = "jwt";
	private static Logger logger = Logger.getLogger(Summary.class.getName());
	private static Utilities utilities = null;

	private @Inject @ConfigProperty(name = "TEST_MODE", defaultValue = "false") boolean testMode;
	private @Inject @RestClient BrokerClient brokerClient;
	private @Inject JsonWebToken jwt;

	//used in the liveness probe
	public static boolean error = false;
	public static String message = null;

	// New liveness probe by @rtclauss
	private static SynchronizedDescriptiveStatistics last1kCalls;
	public static AtomicBoolean IS_FAILED = new AtomicBoolean(false);
	private static final double FAILURE_THRESHOLD = 0.85;

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public Summary() {
		super();
		if(last1kCalls==null){
			last1kCalls = new SynchronizedDescriptiveStatistics(1000);
		}
		if (utilities == null) utilities = new Utilities(logger);
	}

	private void ensureJwtInSession(HttpServletRequest request) {
    	HttpSession session = request.getSession(true);

	    // 1) Token from POST form (implicit or SPA-based login)
	    String tokenParam = request.getParameter(TOKEN);
	    if (tokenParam != null && !tokenParam.isEmpty()) {
	        logger.info("Placing JWT in the http session (from POST form)");
	        session.setAttribute(JWT, tokenParam);
	        return;
	    }
	
	    // 2) OIDC attributes from Liberty (Entra ID via openidConnectClient)
	    String accessTokenAttr = (String) request.getAttribute("com.ibm.websphere.security.oidc.access_token");
	    String idTokenAttr     = (String) request.getAttribute("com.ibm.websphere.security.oidc.id_token");
	    if ((accessTokenAttr != null && !accessTokenAttr.isEmpty()) || (idTokenAttr != null && !idTokenAttr.isEmpty())) {
	        String chosen = (accessTokenAttr != null && !accessTokenAttr.isEmpty()) ? accessTokenAttr : idTokenAttr;
	        session.setAttribute(JWT, chosen);
	        logger.fine("Stored OIDC token from request attributes into session");
	    }
	}
	
	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	@WithSpan
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		if (brokerClient==null) {
			throw new NullPointerException("Injection of BrokerClient failed!");
		}

		try {
            if (Utilities.useOIDC) {
                ensureJwtInSession(request);
				String method = request.getMethod();
                // With some providers (e.g., Keycloak implicit flow), the access_token is POSTed back to this servlet.
                // With Entra ID and Liberty OIDC, tokens are exposed on request attributes instead.
                if (POST.equalsIgnoreCase(method)) {
                    String token = request.getParameter(TOKEN);
                    HttpSession session = request.getSession();
                    if (session!=null && token != null && !token.isEmpty()) {
                        logger.info("Placing JWT in the http session (from POST form)");
                        session.setAttribute(JWT, token);
                        if (logger.isLoggable(Level.FINE)) {
                            Base64.Decoder decoder = Base64.getUrlDecoder();
                            String[] parts = token.split("\\.");
                            String header = new String(decoder.decode(parts[0]));
                            String payload = new String(decoder.decode(parts[1]));
                            logger.fine("access token header = "+header);
                            logger.fine("access token body = "+payload);
                        }
                    }
                }
                // Always try Liberty OIDC request attributes (works for Entra ID)
                String accessTokenAttr = (String) request.getAttribute("com.ibm.websphere.security.oidc.access_token");
                String idTokenAttr     = (String) request.getAttribute("com.ibm.websphere.security.oidc.id_token");
                if ((accessTokenAttr != null && !accessTokenAttr.isEmpty()) || (idTokenAttr != null && !idTokenAttr.isEmpty())) {
                    HttpSession session = request.getSession();
                    if (session != null) {
                        String chosen = (accessTokenAttr != null && !accessTokenAttr.isEmpty()) ? accessTokenAttr : idTokenAttr;
                        session.setAttribute(JWT, chosen);
                        logger.fine("Stored OIDC token from request attributes into session");
                    }
                }

                // If no token is present yet (neither attributes nor session), force OIDC redirect to obtain tokens
                HttpSession preCallSession = request.getSession(false);
                String sessionJwt = (preCallSession == null) ? null : (String) preCallSession.getAttribute(JWT);
                if ((accessTokenAttr == null || accessTokenAttr.isEmpty()) && (idTokenAttr == null || idTokenAttr.isEmpty()) && (sessionJwt == null || sessionJwt.isEmpty())) {
                    logger.warning("No OIDC tokens found; invoking container authentication to start OIDC flow");
                    request.authenticate(response); // lets Liberty start the OIDC flow (sets state/nonce)
                    return;
                }
            } else {
				if (jwt==null) throw new NullPointerException("Injection of JWT failed!");
			}
//			JsonArray portfolios = PortfolioServices.getPortfolios(request);
			logger.fine("Calling brokerClient.getBrokers");

			HttpSession session = request.getSession();
			if(session.getAttribute("page")==null){
				session.setAttribute("page", 1);
			}
			Integer page = (Integer) session.getAttribute("page");
            // Debug which token source will be used and its iss/aud (if available)
            try {
                String dbgAccess = (String) request.getAttribute("com.ibm.websphere.security.oidc.access_token");
                String dbgId     = (String) request.getAttribute("com.ibm.websphere.security.oidc.id_token");
                String dbgSess   = null;
                HttpSession s = request.getSession(false);
                if (s != null) dbgSess = (String) s.getAttribute(JWT);
                String chosen = dbgAccess!=null && !dbgAccess.isEmpty() ? "access_token(attr)"
                               : (dbgId!=null && !dbgId.isEmpty() ? "id_token(attr)" : (dbgSess!=null?"session":"none"));
                String token = utilities.getJWT(jwt, request);
                if (token != null) {
                    String[] parts = token.split("\\.");
                    if (parts.length==3) {
                        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
                        logger.info("Broker call token source="+chosen+", payload="+payload);
                    } else {
                        logger.info("Broker call token source="+chosen+", token is not JWS (parts="+parts.length+")");
                    }
                } else {
                    logger.warning("Broker call token source="+chosen+", but token is null");
                }
            } catch (Throwable ignore) { }

            // NOTE: you need to include the JWT here because we're calling from a Servlet, not a JAX-RS resource
            // JWT is only propagated if a REST Service calls a REST Client.
            List<Broker> brokers = testMode ? getHardcodedBrokers() : brokerClient.getBrokers(utilities.getAuthHeader(jwt, request), page, 10);
			brokers.sort((b1, b2)->
					b1.getOwner().compareToIgnoreCase(b2.getOwner()));

			// set brokers for JSP
			request.setAttribute("brokers", brokers);
			last1kCalls.addValue(1.0);
		} catch (Throwable t) {
			utilities.logException(t);
			message = t.getMessage();
			error = true;
			request.setAttribute("message", message);
			request.setAttribute("error", error);
			last1kCalls.addValue(0.0);
		} finally {
			var mean = last1kCalls.getMean();
			logger.finest("Is failing calc mean: "+ mean);
			if (mean < FAILURE_THRESHOLD) {
				logger.warning("Trader is failing liveness threshold");
				IS_FAILED.set(true);
			} else {
				IS_FAILED.set(false);
			}
		}

        if (response.isCommitted()) {
            logger.fine("Response already committed; skipping forward to JSP");
            return;
        }
        RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/WEB-INF/jsps/summary.jsp");
        dispatcher.forward(request, response);
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	@WithSpan
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		if (Utilities.useOIDC) {
        	ensureJwtInSession(request);
    	}
		String submit = request.getParameter("submit");
		HttpSession session = request.getSession();

		Integer pageNumber = (Integer)session.getAttribute("page");
		logger.fine("Page number is set to: "+ pageNumber);
		if(pageNumber == null || pageNumber <= 0){
			logger.severe("Invalid page number. Setting to Page 1.");
			pageNumber = 1;
			session.setAttribute("page", pageNumber);
			doGet(request, response);
		}

		if (submit != null) {
			if (submit.equals(LOGOUT)) {
				request.logout();
				// Need to retrieve the session before it is invalidated.
				session = request.getSession();
				try {
					if (session != null) session.invalidate();
				} catch(IllegalStateException ise){
					logger.fine("Session was invalidated as part of logout.");
				}
				response.sendRedirect("login");
			} else if(submit.equals(PREVIOUS)){
				session.setAttribute("page",pageNumber-1);
				doGet(request, response);
			} else if(submit.equals(NEXT)){
				session.setAttribute("page",pageNumber+1);
				doGet(request, response);
			} else {
				String action = request.getParameter("action");
				String owner = request.getParameter("owner");
				logger.fine("Action is: " + action);
				if (action != null) {
					if (action.equals(CREATE)) {
						response.sendRedirect("addPortfolio"); //send control to the AddPortfolio servlet
					} else if (action.equals(RETRIEVE)) {
						response.sendRedirect("viewPortfolio?owner="+owner); //send control to the ViewPortfolio servlet
					} else if (action.equals(UPDATE)) {
						response.sendRedirect("addStock?owner="+owner+"&source=summary"); //send control to the AddStock servlet
					} else if (action.equals(DELETE)) {
//						PortfolioServices.deletePortfolio(request, owner);
						brokerClient.deleteBroker(utilities.getAuthHeader(jwt, request), owner);
						doGet(request, response); //refresh the Summary servlet
					} else {
						doGet(request, response); //something went wrong - just refresh the Summary servlet
					}
				} else {
					doGet(request, response); //something went wrong - just refresh the Summary servlet
				}
			}
		} else {
			doGet(request, response); //something went wrong - just refresh the Summary servlet
		}
	}

	List<Broker> getHardcodedBrokers() {
		Broker john = new Broker("John");
		john.setTotal(1234.56);
		john.setLoyalty("Basic");
		Broker karri = new Broker("Karri");
		karri.setTotal(12345.67);
		karri.setLoyalty("Bronze");
		Broker ryan = new Broker("Ryan");
		ryan.setTotal(23456.78);
		ryan.setLoyalty("Bronze");
		Broker anand = new Broker("Anand");
		anand.setTotal(98765.43);
		anand.setLoyalty("Silver");
		Broker greg = new Broker("Greg");
		greg.setTotal(123456.78);
		greg.setLoyalty("Gold");
		Broker eric = new Broker("Eric");
		eric.setTotal(1234567.89);
		eric.setLoyalty("Platinum");
		List<Broker> brokers = Arrays.asList(john, karri, ryan, anand, greg, eric);
		return brokers;
	}
}
