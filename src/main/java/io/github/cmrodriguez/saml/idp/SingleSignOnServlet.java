package io.github.cmrodriguez.saml.idp;

import java.io.IOException;
import java.io.Writer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SingleSignOnServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static Logger logger = LoggerFactory.getLogger(SingleSignOnServlet.class);

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		logger.info("AuthnRequest recieved");
		Writer w = resp.getWriter();
		resp.setContentType("text/html");
		w.append("<html>" + "<head></head>"
				+ "<body><h1>Identity Provider</h1><h2>Please authenticate</h2> <form method=\"POST\" ACTION=\""
				+ IDPConstants.SSO_SERVICE + "\">");
		w.append("<input type=\"submit\" value=\"Authenticate\"/>" + "</form>" + "</body>" + "</html>");
	}

	@Override
	protected void doPost(final HttpServletRequest req, final HttpServletResponse resp)
			throws ServletException, IOException {
		String location = IDPConstants.ASSERTION_CONSUMER_SERVICE
				+ "?SAMLart=AAQAAMFbLinlXaCM%2BFIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg%3D";
		logger.info("Post recieved! Redirecting to: " + location);

		resp.sendRedirect(location);
	}

}
